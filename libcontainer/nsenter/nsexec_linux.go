package nsenter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/nsenter/internal/nofile"
)

// List of netlink message types sent to us as part of bootstrapping the init.
// These constants are defined in libcontainer/message_linux.go.
const (
	initMsg          = 62000
	cloneFlagsAttr   = 27281
	nsPathsAttr      = 27282
	uidmapAttr       = 27283
	gidmapAttr       = 27284
	setgroupAttr     = 27285
	oomScoreAdjAttr  = 27286
	rootlessEUIDAttr = 27287
	uidmapPathAttr   = 27288
	gidmapPathAttr   = 27289
	timeNsOffsetAttr = 27290
)

// stage2Env is set by stage-0 for the re-executed runc init (stage-2), so
// that it knows the namespaces are already set up. Its value is "1" if the
// process has to be made non-dumpable, and "0" otherwise.
const stage2Env = "_LIBCONTAINER_NSEXEC_DONE"

type nlConfig struct {
	cloneFlags     uint32
	oomScoreAdj    string
	uidmap         string
	gidmap         string
	namespaces     string
	isSetgroup     bool
	isRootlessEUID bool
	uidmapPath     string
	gidmapPath     string
	timeNsOffset   string
}

type nsEntry struct {
	fd    int
	typ   uintptr
	name  string
	path  string
	label string // "type:path", for error messages.
}

var allNsTypes = []struct {
	typ  uintptr
	name string
}{
	{unix.CLONE_NEWCGROUP, "cgroup"},
	{unix.CLONE_NEWIPC, "ipc"},
	{unix.CLONE_NEWNS, "mnt"},
	{unix.CLONE_NEWNET, "net"},
	{unix.CLONE_NEWPID, "pid"},
	{unix.CLONE_NEWTIME, "time"},
	{unix.CLONE_NEWUSER, "user"},
	{unix.CLONE_NEWUTS, "uts"},
}

// nstype returns the clone(2) flag for a namespace, given its name.
func nstype(name string) (uintptr, bool) {
	for _, ns := range allNsTypes {
		if ns.name == name {
			return ns.typ, true
		}
	}
	return 0, false
}

func nssetToStr(set uintptr) string {
	var names []string
	for _, ns := range allNsTypes {
		if ns.typ&set != 0 {
			names = append(names, ns.name)
		}
	}
	return strings.Join(names, ", ")
}

// stage0 holds the state of the topmost nsexec process.
type stage0 struct {
	pipenum   int
	cfg       nlConfig
	ns        []nsEntry
	stage1Pid int
	stage2Pid int
}

func (s *stage0) killChildren() {
	for _, pid := range []int{s.stage1Pid, s.stage2Pid} {
		if pid > 0 {
			_ = unix.Kill(pid, unix.SIGKILL)
		}
	}
}

func (s *stage0) bail(format string, args ...any) {
	s.killChildren()
	bail(format, args...)
}

func readFull(fd int, buf []byte) (int, error) {
	return io.ReadFull(rawFd(fd), buf)
}

// rawFd implements io.Reader on top of a raw file descriptor. It is used
// instead of os.File, which might change the fd mode or close the fd.
type rawFd int

func (fd rawFd) Read(b []byte) (int, error) {
	for {
		n, err := unix.Read(int(fd), b)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 && len(b) > 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

func writeAll(fd int, b []byte) error {
	for len(b) > 0 {
		n, err := unix.Write(fd, b)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func cstr(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func parseNetlink(fd int) nlConfig {
	var cfg nlConfig
	ne := binary.NativeEndian

	// Retrieve the netlink header.
	hdr := make([]byte, unix.NLMSG_HDRLEN)
	if n, err := readFull(fd, hdr); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			bail("failed to read netlink header (got %d of %d bytes)", n, len(hdr))
		}
		bail("failed to read netlink header: %v", err)
	}
	msgLen := ne.Uint32(hdr[0:4])
	msgType := ne.Uint16(hdr[4:6])
	if msgType == unix.NLMSG_ERROR {
		bail("failed to read netlink message")
	}
	if msgType != initMsg {
		bail("unexpected msg type %d", msgType)
	}
	if msgLen < unix.NLMSG_HDRLEN {
		bail("invalid netlink message length %d", msgLen)
	}

	// Retrieve data.
	data := make([]byte, msgLen-unix.NLMSG_HDRLEN)
	if n, err := readFull(fd, data); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			bail("failed to read netlink payload (got %d of %d bytes)", n, len(data))
		}
		bail("failed to read netlink payload: %v", err)
	}

	// Parse the netlink payload.
	for len(data) >= unix.NLA_HDRLEN {
		nlaLen := int(ne.Uint16(data[0:2]))
		nlaType := ne.Uint16(data[2:4])
		if nlaLen < unix.NLA_HDRLEN || nlaLen > len(data) {
			bail("invalid netlink attribute length %d", nlaLen)
		}
		payload := data[unix.NLA_HDRLEN:nlaLen]

		switch nlaType {
		case cloneFlagsAttr:
			if len(payload) < 4 {
				bail("invalid clone flags attribute")
			}
			cfg.cloneFlags = ne.Uint32(payload)
		case rootlessEUIDAttr:
			cfg.isRootlessEUID = len(payload) > 0 && payload[0] != 0
		case oomScoreAdjAttr:
			cfg.oomScoreAdj = cstr(payload)
		case nsPathsAttr:
			cfg.namespaces = cstr(payload)
			if cfg.namespaces == "" {
				bail("ns paths are empty")
			}
		case uidmapAttr:
			cfg.uidmap = cstr(payload)
		case gidmapAttr:
			cfg.gidmap = cstr(payload)
		case uidmapPathAttr:
			cfg.uidmapPath = cstr(payload)
		case gidmapPathAttr:
			cfg.gidmapPath = cstr(payload)
		case setgroupAttr:
			cfg.isSetgroup = len(payload) > 0 && payload[0] != 0
		case timeNsOffsetAttr:
			cfg.timeNsOffset = cstr(payload)
		default:
			bail("unknown netlink message type %d", nlaType)
		}

		adv := (nlaLen + unix.NLA_ALIGNTO - 1) &^ (unix.NLA_ALIGNTO - 1)
		if adv > len(data) {
			adv = len(data)
		}
		data = data[adv:]
	}
	return cfg
}

// openNamespaces opens the namespace files. We have to open the file
// descriptors first, since after we join the mnt or user namespaces we might
// no longer be able to access the paths.
func openNamespaces(nsspec string) []nsEntry {
	var list []nsEntry
	for _, spec := range strings.Split(nsspec, ",") {
		if spec == "" {
			bail("ns paths are empty")
		}
		name, path, ok := strings.Cut(spec, ":")
		if !ok {
			bail("failed to parse %s", spec)
		}
		typ, ok := nstype(name)
		if !ok {
			// setns(2) lets us join namespaces without knowing the type,
			// but namespaces usually require special handling of some kind
			// and the rest of runc doesn't allow unknown namespace types.
			bail("unknown namespace type %s", name)
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			bail("failed to open %s: %v", path, err)
		}
		list = append(list, nsEntry{fd: fd, typ: typ, name: name, path: path, label: spec})
	}
	if len(list) > 64 {
		bail("too many namespaces to join: %d", len(list))
	}
	return list
}

func writeFile(path, data string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(data)
	if err2 := f.Close(); err == nil {
		err = err2
	}
	return err
}

// updateSetgroups must be called before we touch gid_map.
func (s *stage0) updateSetgroups(pid int, policy string) {
	path := "/proc/" + strconv.Itoa(pid) + "/setgroups"
	if err := writeFile(path, policy); err != nil {
		// If the kernel is too old to support /proc/pid/setgroups,
		// open(2) or write(2) will return ENOENT. This is fine.
		if !errors.Is(err, unix.ENOENT) {
			s.bail("failed to write '%s' to %s: %v", policy, path, err)
		}
	}
}

func (s *stage0) tryMappingTool(app string, pid int, idmap string) error {
	// If app is empty, this usually is a configuration or programming issue.
	if app == "" {
		s.bail("mapping tool not present")
	}
	const maxArgs = 20
	args := []string{strconv.Itoa(pid)}
	// Convert the map string into a list of arguments that
	// newuidmap/newgidmap can understand.
	for _, f := range strings.FieldsFunc(idmap, func(r rune) bool { return r == ' ' || r == '\n' }) {
		if len(args)+1 >= maxArgs-1 {
			break
		}
		args = append(args, f)
	}
	cmd := exec.Command(app, args...)
	cmd.Env = []string{}
	return cmd.Run()
}

func (s *stage0) updateIDMap(kind, tool string, pid int, idmap string) {
	if idmap == "" {
		return
	}
	path := "/proc/" + strconv.Itoa(pid) + "/" + kind + "_map"
	logDebug("update %s to '%s'", path, idmap)
	if err := writeFile(path, idmap); err != nil {
		if !errors.Is(err, unix.EPERM) {
			s.bail("failed to update %s: %v", path, err)
		}
		logDebug("update %s got -EPERM (trying %s)", path, tool)
		if err := s.tryMappingTool(tool, pid, idmap); err != nil {
			s.bail("failed to use new%s map on %d: %v", kind, pid, err)
		}
	}
}

func updateOomScoreAdj(val string) {
	if val == "" {
		return
	}
	logDebug("update /proc/self/oom_score_adj to '%s'", val)
	if err := writeFile("/proc/self/oom_score_adj", val); err != nil {
		bail("failed to update /proc/self/oom_score_adj: %v", err)
	}
}

func (s *stage0) updateTimeNsOffsets(pid int) {
	if s.cfg.timeNsOffset == "" {
		return
	}
	path := "/proc/" + strconv.Itoa(pid) + "/timens_offsets"
	logDebug("update %s to '%s'", path, s.cfg.timeNsOffset)
	if err := writeFile(path, s.cfg.timeNsOffset); err != nil {
		s.bail("failed to update %s: %v", path, err)
	}
}

// nondumpGid returns a non-zero gid which is likely valid in the container
// user namespace, or -1. See prepareNondumpExec.
func (s *stage0) nondumpGid() int {
	if s.cfg.gidmap != "" {
		// A new user namespace, so we know the mapping.
		for _, line := range strings.Split(s.cfg.gidmap, "\n") {
			var inside, outside, count int
			if n, _ := fmt.Sscanf(line, "%d %d %d", &inside, &outside, &count); n != 3 || count < 1 {
				continue
			}
			if inside != 0 {
				return inside
			}
			if count > 1 {
				return inside + 1
			}
		}
		return -1
	}
	// Either no user namespace, or we are joining an existing one.
	// The overflow gid is commonly mapped.
	return 65534
}

func logCPUAffinity() {
	if !logEnabledFor(levelDebug) {
		return
	}
	var cpus unix.CPUSet
	if err := unix.SchedGetaffinity(0, &cpus); err != nil {
		writeLog(levelWarning, "sched_getaffinity: %v", err)
		return
	}
	// Do not print the complete mask, we only need a few first CPUs.
	var mask uint64
	for i := range 64 {
		if cpus.IsSet(i) {
			mask |= 1 << i
		}
	}
	logDebug("affinity: 0x%x", mask)
}

func cstring(s string) *byte {
	p, err := unix.BytePtrFromString(s)
	if err != nil {
		bail("invalid string %q: %v", s, err)
	}
	return p
}

func (s *stage0) readSync(fd int, what string) (syncMsg, bool) {
	var msg syncMsg
	buf := make([]byte, syncMsgSize)
	n, err := readFull(fd, buf)
	if err != nil {
		if n == 0 && errors.Is(err, io.EOF) {
			return msg, false
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			s.bail("%s (got %d of %d bytes)", what, n, len(buf))
		}
		s.bail("%s: %v", what, err)
	}
	ne := binary.NativeEndian
	msg.Type = ne.Uint32(buf[0:])
	msg.Arg0 = ne.Uint32(buf[4:])
	msg.Arg1 = ne.Uint32(buf[8:])
	msg.Arg2 = ne.Uint32(buf[12:])
	return msg, true
}

func (s *stage0) writeSync(fd int, typ uint32, what string) {
	buf := make([]byte, syncMsgSize)
	binary.NativeEndian.PutUint32(buf, typ)
	if err := writeAll(fd, buf); err != nil {
		s.bail("%s: %v", what, err)
	}
}

// childError converts an error reported by stage-1 or stage-2 to a message.
func (s *stage0) childError(stage string, msg syncMsg) string {
	errno := unix.Errno(msg.Arg0)
	switch msg.Arg1 {
	case stepSyncWrite:
		return fmt.Sprintf("%s: failed to sync with parent: write(%#x): %v", stage, msg.Arg2, errno)
	case stepSyncRead:
		return fmt.Sprintf("%s: failed to sync with parent: read(%#x): %v", stage, msg.Arg2, errno)
	case stepSyncUnexpected:
		return fmt.Sprintf("%s: failed to sync with parent: unexpected sync value %#x", stage, msg.Arg2)
	case stepSetns:
		name := "unknown"
		if int(msg.Arg2) < len(s.ns) {
			name = s.ns[msg.Arg2].name
		}
		return fmt.Sprintf("failed to setns into %s namespace: %v", name, errno)
	case stepJoinNamespaces:
		var failed uintptr
		for i, ns := range s.ns {
			if msg.Arg2&(1<<uint(i)) == 0 {
				failed |= ns.typ
				writeLog(levelFatal, "failed to setns(%#x) into %s namespace (with path %s): %v",
					ns.typ, ns.name, ns.path, unix.EPERM)
			}
		}
		return fmt.Sprintf("failed to join {%s} namespaces: %v", nssetToStr(failed), errno)
	case stepSetresuidUserns:
		return fmt.Sprintf("failed to become root in user namespace: %v", errno)
	case stepUnshareUserns:
		return fmt.Sprintf("failed to unshare user namespace: %v", errno)
	case stepSetDumpable:
		return fmt.Sprintf("failed to set process as dumpable=%d: %v", msg.Arg2, errno)
	case stepUnshare:
		return fmt.Sprintf("failed to unshare remaining namespaces: %v", errno)
	case stepCloneStage2:
		return fmt.Sprintf("unable to spawn stage-2: %v", errno)
	case stepSetsid:
		return fmt.Sprintf("setsid failed: %v", errno)
	case stepSetuid:
		return fmt.Sprintf("setuid failed: %v", errno)
	case stepSetgid:
		return fmt.Sprintf("setgid failed: %v", errno)
	case stepSetgroups:
		return fmt.Sprintf("setgroups failed: %v", errno)
	case stepSetrlimit:
		return fmt.Sprintf("failed to restore RLIMIT_NOFILE: %v", errno)
	case stepNondumpable:
		return fmt.Sprintf("unable to make sure runc init is non-dumpable after execve "+
			"(no_new_privs or SECURE_NOROOT are set, and there's no second gid mapped): %v", errno)
	case stepMntnsFd:
		return fmt.Sprintf("failed to clear O_CLOEXEC on mnt namespace fd: %v", errno)
	case stepExec:
		return fmt.Sprintf("failed to re-execute runc init: %v", errno)
	}
	return fmt.Sprintf("%s: unknown error (step %d): %v", stage, msg.Arg1, errno)
}

// nsexec is the Go implementation of what used to be nsexec.c. It is run in
// a newly started "runc init" (stage-0) and never returns.
//
// Stage-0 reads the bootstrap data from the init pipe and spawns stage-1,
// which joins and creates namespaces and, in turn, spawns stage-2. Stage-1
// and stage-2 are created with a raw clone(2) and can only do raw system
// calls (the Go runtime can not be used in a forked child of a multi-threaded
// process). Stage-2 does the final setup and then re-executes runc init,
// which then runs the Go part of the container initialization in the new
// namespaces.
func nsexec(pipenum int) {
	s := &stage0{pipenum: pipenum}

	logDebug("=> nsexec container setup")

	// Log initial CPU affinity, this is solely for the tests in
	// ../../tests/integration/cpu_affinity.bats.
	logCPUAffinity()

	// Parse all of the netlink configuration.
	s.cfg = parseNetlink(pipenum)

	// Set oom_score_adj. This has to be done before !dumpable because
	// /proc/self/oom_score_adj is not writeable unless you're an privileged
	// user (if !dumpable is set). All children inherit their parent's
	// oom_score_adj value on fork(2) so this will always be propagated
	// properly.
	updateOomScoreAdj(s.cfg.oomScoreAdj)

	// Make the process non-dumpable, to avoid various race conditions that
	// could cause processes in namespaces we're joining to access host
	// resources (or potentially execute code).
	//
	// However, if the number of namespaces we are joining is 0, we are not
	// going to be switching to a different security context. Thus setting
	// ourselves to be non-dumpable only breaks things (like rootless
	// containers), which is the recommendation from the kernel folks.
	nonDumpable := s.cfg.namespaces != ""
	if nonDumpable {
		logDebug("set process as non-dumpable")
		if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
			bail("failed to set process as non-dumpable: %v", err)
		}
		s.ns = openNamespaces(s.cfg.namespaces)
	}

	// Stage-2 re-executes the runc binary. If we joined an existing mount
	// namespace (the container's one) before that, the kernel would look
	// up the ELF interpreter of a dynamically linked binary (and then the
	// interpreter would load shared libraries) in it. Not only this does
	// not work, it must never be allowed to, since the files there are
	// controlled by the container. So, the existing mount namespace is
	// joined by the re-executed runc init instead (see stage2Init).
	//
	// Note that creating a new mount namespace (unshare(CLONE_NEWNS)) is
	// fine, as it is a copy of the current one.
	mntnsFd := -1
	for i, ns := range s.ns {
		if ns.typ == unix.CLONE_NEWNS {
			mntnsFd = ns.fd
			s.ns = append(s.ns[:i], s.ns[i+1:]...)
			break
		}
	}

	a := &childArgs{
		cloneFlags:     uintptr(s.cfg.cloneFlags) &^ unix.CLONE_NEWUSER,
		newUserns:      s.cfg.cloneFlags&unix.CLONE_NEWUSER != 0,
		toggleDumpable: nonDumpable,
		timens:         s.cfg.timeNsOffset != "",
		setgroups:      !s.cfg.isRootlessEUID && s.cfg.isSetgroup,
		// It's only required when joining namespaces, as otherwise the
		// process is dumpable anyway (see above), but it's always
		// attempted, to minimize exposure.
		nondumpRequired: nonDumpable,
		nondumpGid:      s.nondumpGid(),
		emptyPath:       cstring(""),
		stage1Name:      cstring("runc:[1:CHILD]"),
		stage2Name:      cstring("runc:[2:INIT]"),
		mntnsFd:         mntnsFd,
	}
	for _, ns := range s.ns {
		a.nsFds = append(a.nsFds, ns.fd)
		a.nsTypes = append(a.nsTypes, ns.typ)
	}
	if nofile.Valid {
		a.restoreNofile = true
		a.nofile = rlimit64{Cur: nofile.Cur, Max: nofile.Max}
		// The hard limit could have been changed since; only restore
		// the soft limit.
		var cur unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &cur); err == nil {
			a.nofile.Max = cur.Max
			if a.nofile.Cur > a.nofile.Max {
				a.nofile.Cur = a.nofile.Max
			}
		}
	}

	// Prepare execveat(2) arguments for stage-2.
	exeFd, err := unix.Open("/proc/self/exe", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		bail("failed to open /proc/self/exe: %v", err)
	}
	a.exeFd = exeFd
	a.argv, err = syscall.SlicePtrFromStrings(os.Args)
	if err != nil {
		bail("invalid argv: %v", err)
	}
	dumpVal := "0"
	if nonDumpable {
		dumpVal = "1"
	}
	env := append(os.Environ(), stage2Env+"="+dumpVal)
	if mntnsFd >= 0 {
		env = append(env, mntnsEnv+"="+strconv.Itoa(mntnsFd))
	}
	// If execve(2) regains a capability (see prepareNondumpExec), the
	// kernel clears some personality flags, so pass it to be restored.
	if pers, _, errno := unix.RawSyscall(unix.SYS_PERSONALITY, 0xffffffff, 0, 0); errno == 0 {
		env = append(env, personalityEnv+"="+strconv.FormatUint(uint64(pers), 10))
	}
	a.envv, err = syscall.SlicePtrFromStrings(env)
	if err != nil {
		bail("invalid environment: %v", err)
	}

	// Socket pairs to sync with the child and grandchild.
	childPair, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		bail("failed to setup sync pipe between parent and child: %v", err)
	}
	grandchildPair, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		bail("failed to setup sync pipe between parent and grandchild: %v", err)
	}
	a.syncChild = [2]int{childPair[0], childPair[1]}
	a.syncGrandchild = [2]int{grandchildPair[0], grandchildPair[1]}

	// Stage-0: our job is just to create a new child (stage-1) and write
	// its uid_map and gid_map. That process will go on to create a new
	// process (stage-2), then it will send us its PID which we will send
	// to the bootstrap process.
	setStage("nsexec-0")
	_ = unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(cstring("runc:[0:PARENT]"))), 0, 0, 0)
	logDebug("~> nsexec stage-0")
	logDebug("spawn stage-1")

	pid, errno := spawnChildren(a)
	if errno != 0 {
		bail("unable to spawn stage-1: %v", errno)
	}
	s.stage1Pid = int(pid)

	// Close the fds which are only used by the children.
	_ = unix.Close(a.syncChild[0])
	for _, ns := range s.ns {
		_ = unix.Close(ns.fd)
	}
	if mntnsFd >= 0 {
		_ = unix.Close(mntnsFd)
	}
	_ = unix.Close(exeFd)

	// State machine for synchronisation with the children. We only return
	// once both the child and grandchild are ready.
	syncfd := a.syncChild[1]
	logDebug("-> stage-1 synchronisation loop")
	for stage1Complete := false; !stage1Complete; {
		msg, ok := s.readSync(syncfd, "failed to sync with stage-1: next state")
		if !ok {
			s.bail("failed to sync with stage-1: next state: unexpected EOF")
		}
		switch msg.Type {
		case syncUsermapPls:
			logDebug("stage-1 requested userns mappings")
			// Enable setgroups(2) if we've been asked to. But we also
			// have to explicitly disable setgroups(2) if we're creating
			// a rootless container for single-entry mapping (i.e.
			// config.is_setgroup == false), this is required since
			// Linux 3.19.
			//
			// For rootless multi-entry mapping, config.is_setgroup shall
			// be true and newuidmap/newgidmap shall be used.
			if s.cfg.isRootlessEUID && !s.cfg.isSetgroup {
				s.updateSetgroups(s.stage1Pid, "deny")
			}
			// Set up mappings.
			s.updateIDMap("uid", s.cfg.uidmapPath, s.stage1Pid, s.cfg.uidmap)
			s.updateIDMap("gid", s.cfg.gidmapPath, s.stage1Pid, s.cfg.gidmap)
			s.writeSync(syncfd, syncUsermapAck, "failed to sync with stage-1: write(SYNC_USERMAP_ACK)")
		case syncRecvPidPls:
			logDebug("stage-1 requested pid to be forwarded")
			s.stage2Pid = int(int32(msg.Arg0))
			s.writeSync(syncfd, syncRecvPidAck, "failed to sync with stage-1: write(SYNC_RECVPID_ACK)")
			// Send both the stage-1 and stage-2 pids back to runc. runc
			// needs the stage-2 to continue process management, but
			// because stage-1 was spawned with CLONE_PARENT we cannot
			// reap it within stage-0 and thus we need to ask runc to
			// reap the zombie for us.
			logDebug("forward stage-1 (%d) and stage-2 (%d) pids to runc", s.stage1Pid, s.stage2Pid)
			js := fmt.Sprintf("{\"stage1_pid\":%d,\"stage2_pid\":%d}\n", s.stage1Pid, s.stage2Pid)
			if err := writeAll(pipenum, []byte(js)); err != nil {
				s.bail("failed to sync with runc: write(pid-JSON): %v", err)
			}
		case syncTimeOffsetsPls:
			logDebug("stage-1 requested timens offsets to be configured")
			s.updateTimeNsOffsets(s.stage1Pid)
			s.writeSync(syncfd, syncTimeOffsetsAck, "failed to sync with child: write(SYNC_TIMEOFFSETS_ACK)")
		case syncChildFinish:
			logDebug("stage-1 complete")
			stage1Complete = true
			s.stage1Pid = -1
		case syncError:
			s.bail("%s", s.childError("stage-1", msg))
		default:
			s.bail("unexpected sync value: %#x", msg.Type)
		}
	}
	logDebug("<- stage-1 synchronisation loop")

	// Now sync with grandchild.
	_ = unix.Close(a.syncChild[1])
	_ = unix.Close(a.syncGrandchild[0])
	syncfd = a.syncGrandchild[1]

	logDebug("-> stage-2 synchronisation loop")
	logDebug("signalling stage-2 to run")
	s.writeSync(syncfd, syncGrandchild, "failed to sync with child: write(SYNC_GRANDCHILD)")
	msg, ok := s.readSync(syncfd, "failed to sync with child: next state")
	if !ok {
		s.bail("failed to sync with stage-2: unexpected EOF")
	}
	switch msg.Type {
	case syncChildFinish:
		switch msg.Arg0 {
		case nondumpCaps:
			logDebug("stage-2 will be non-dumpable after exec (capability regained)")
		case nondumpGid:
			logDebug("stage-2 will be non-dumpable after exec (real and effective gids differ)")
		default:
			logDebug("stage-2 will be dumpable after exec")
		}
	case syncError:
		s.bail("%s", s.childError("stage-2", msg))
	default:
		s.bail("unexpected sync value: %#x", msg.Type)
	}
	// Stage-2 is about to execute runc init; the sync socket is O_CLOEXEC,
	// so we get EOF once it succeeded, or an error message otherwise.
	msg, ok = s.readSync(syncfd, "failed to sync with child: exec")
	if ok {
		if msg.Type == syncError {
			s.bail("%s", s.childError("stage-2", msg))
		}
		s.bail("unexpected sync value: %#x", msg.Type)
	}
	logDebug("stage-2 complete")
	logDebug("<- stage-2 synchronisation loop")
	logDebug("<~ nsexec stage-0")
	logDebug("<= nsexec container setup")
	// Use unix.Exit rather than os.Exit to avoid calling runtime exit
	// hooks and racefini(); under -race, __tsan::Finalize sleeps for
	// atexit_sleep_ms (1s by default) on every container start/exec.
	unix.Exit(0)
}
