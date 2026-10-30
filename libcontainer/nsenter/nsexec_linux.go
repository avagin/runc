package nsenter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/nsenter/internal/nofile"
)

// Config describes how to spawn a container init or setns process.
type Config struct {
	// Exe is an open file handle to the runc binary to execute in stage-2.
	// If nil, /proc/self/exe is used.
	Exe *os.File

	// Args and Env are the command-line arguments and environment for stage-2.
	// If Args is empty, os.Args is used. If Env is nil, os.Environ() is used.
	Args []string
	Env  []string

	// Dir is the working directory to chdir(2) into in stage-1 before
	// joining or unsharing namespaces.
	Dir string

	// Standard I/O and extra file descriptors to pass to stage-2 at
	// fds 0, 1, 2, and 3 .. 3+len(ExtraFiles)-1.
	Stdin      *os.File
	Stdout     *os.File
	Stderr     *os.File
	ExtraFiles []*os.File

	// Pdeathsig, if non-zero, is set via PR_SET_PDEATHSIG in stage-2.
	Pdeathsig unix.Signal

	// CloneFlags are the CLONE_NEW* flags for namespaces to unshare.
	CloneFlags uintptr
	// Namespaces is the list of existing namespaces to join ("type:path").
	Namespaces []string

	// User namespace ID mappings and helper binary paths.
	UIDMap       string
	GIDMap       string
	UIDMapPath   string
	GIDMapPath   string
	Setgroups    bool
	RootlessEUID bool

	// OomScoreAdj, if non-nil, is written to stage-1's oom_score_adj.
	OomScoreAdj *int
	// TimeOffsets is the content to write to stage-1's timens_offsets.
	TimeOffsets string

	// UseCgroupFD and CgroupFD configure clone3(CLONE_INTO_CGROUP) when
	// spawning stage-1. If clone3 fails, Exec falls back to clone(2) and
	// sets UseCgroupFD to false.
	UseCgroupFD bool
	CgroupFD    int

	// PrepareStage1, if non-nil, is called in the parent after stage-1 is
	// cloned (while it is still in the host namespaces and dumpable) and
	// before it joins or unshares namespaces.
	PrepareStage1 func(pid int) error
}

type nsEntry struct {
	fd   int
	typ  uintptr
	name string
	path string
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

type nsexec struct {
	cfg            *Config
	ns             []nsEntry
	mntnsFd        int
	ownExeFd       int
	syncChild      [2]int
	syncGrandchild [2]int
	stage1Pid      int
	stage2Pid      int
	stage2Proc     *os.Process
}

func closeFd(fd *int) {
	if *fd >= 0 {
		_ = unix.Close(*fd)
		*fd = -1
	}
}

func reapPid(pid int) {
	if pid <= 0 {
		return
	}
	for {
		if _, err := unix.Wait4(pid, nil, 0, nil); err != unix.EINTR {
			return
		}
	}
}

func (s *nsexec) closeChildFds() {
	closeFd(&s.syncChild[0])
	closeFd(&s.syncGrandchild[0])
	for i := range s.ns {
		closeFd(&s.ns[i].fd)
	}
	closeFd(&s.mntnsFd)
	closeFd(&s.ownExeFd)
}

func (s *nsexec) cleanup(failed bool) {
	s.closeChildFds()
	closeFd(&s.syncChild[1])
	closeFd(&s.syncGrandchild[1])
	if failed {
		if s.stage1Pid > 0 {
			_ = unix.Kill(s.stage1Pid, unix.SIGKILL)
			reapPid(s.stage1Pid)
			s.stage1Pid = -1
		}
		if s.stage2Proc != nil {
			_ = s.stage2Proc.Kill()
			_, _ = s.stage2Proc.Wait()
			s.stage2Proc = nil
			s.stage2Pid = -1
		} else if s.stage2Pid > 0 {
			_ = unix.Kill(s.stage2Pid, unix.SIGKILL)
			reapPid(s.stage2Pid)
			s.stage2Pid = -1
		}
	}
}

func readFull(fd int, buf []byte) (int, error) {
	return io.ReadFull(rawFd(fd), buf)
}

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

// openNamespaces opens the namespace files. We open the file descriptors in
// the parent before forking stage-1, since after stage-1 joins the mnt or
// user namespaces it might no longer be able to access the paths.
func (s *nsexec) openNamespaces(namespaces []string) error {
	for _, spec := range namespaces {
		if spec == "" {
			return errors.New("ns paths are empty")
		}
		name, path, ok := strings.Cut(spec, ":")
		if !ok {
			return fmt.Errorf("failed to parse %s", spec)
		}
		typ, ok := nstype(name)
		if !ok {
			return fmt.Errorf("unknown namespace type %s", name)
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", path, err)
		}
		s.ns = append(s.ns, nsEntry{fd: fd, typ: typ, name: name, path: path})
	}
	if len(s.ns) > 64 {
		return fmt.Errorf("too many namespaces to join: %d", len(s.ns))
	}
	return nil
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
func (s *nsexec) updateSetgroups(pid int, policy string) error {
	path := "/proc/" + strconv.Itoa(pid) + "/setgroups"
	if err := writeFile(path, policy); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("failed to write '%s' to %s: %w", policy, path, err)
	}
	return nil
}

func (s *nsexec) tryMappingTool(app string, pid int, idmap string) error {
	if app == "" {
		return errors.New("mapping tool not present")
	}
	const maxArgs = 20
	args := []string{strconv.Itoa(pid)}
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

func (s *nsexec) updateIDMap(kind, tool string, pid int, idmap string) error {
	if idmap == "" {
		return nil
	}
	path := "/proc/" + strconv.Itoa(pid) + "/" + kind + "_map"
	logrus.Debugf("nsexec: update %s to '%s'", path, idmap)
	if err := writeFile(path, idmap); err != nil {
		if !errors.Is(err, unix.EPERM) {
			return fmt.Errorf("failed to update %s: %w", path, err)
		}
		logrus.Debugf("nsexec: update %s got -EPERM (trying %s)", path, tool)
		if err := s.tryMappingTool(tool, pid, idmap); err != nil {
			return fmt.Errorf("failed to use new%s map on %d: %w", kind, pid, err)
		}
	}
	return nil
}

func (s *nsexec) updateOomScoreAdj(pid int) error {
	if s.cfg.OomScoreAdj == nil {
		return nil
	}
	val := strconv.Itoa(*s.cfg.OomScoreAdj)
	path := "/proc/" + strconv.Itoa(pid) + "/oom_score_adj"
	logrus.Debugf("nsexec: update %s to '%s'", path, val)
	if err := writeFile(path, val); err != nil {
		return fmt.Errorf("failed to update %s: %w", path, err)
	}
	return nil
}

func (s *nsexec) updateTimeNsOffsets(pid int) error {
	if s.cfg.TimeOffsets == "" {
		return nil
	}
	path := "/proc/" + strconv.Itoa(pid) + "/timens_offsets"
	logrus.Debugf("nsexec: update %s to '%s'", path, s.cfg.TimeOffsets)
	if err := writeFile(path, s.cfg.TimeOffsets); err != nil {
		return fmt.Errorf("failed to update %s: %w", path, err)
	}
	return nil
}

// nondumpGid returns a non-zero gid which is likely valid in the container
// user namespace, or -1. See prepareNondumpExec.
func (s *nsexec) nondumpGid() int {
	if s.cfg.GIDMap != "" {
		for _, line := range strings.Split(s.cfg.GIDMap, "\n") {
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
	return 65534
}

func logCPUAffinity() {
	if !logrus.IsLevelEnabled(logrus.DebugLevel) {
		return
	}
	var cpus unix.CPUSet
	if err := unix.SchedGetaffinity(0, &cpus); err != nil {
		logrus.Warnf("nsexec: sched_getaffinity: %v", err)
		return
	}
	// Do not print the complete mask, we only need a few first CPUs.
	var mask uint64
	for i := range 64 {
		if cpus.IsSet(i) {
			mask |= 1 << i
		}
	}
	logrus.Debugf("nsexec: affinity: 0x%x", mask)
}

func (s *nsexec) readSync(fd int, what string) (syncMsg, bool, error) {
	var msg syncMsg
	buf := make([]byte, syncMsgSize)
	n, err := readFull(fd, buf)
	if err != nil {
		if n == 0 && errors.Is(err, io.EOF) {
			return msg, false, nil
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return msg, false, fmt.Errorf("%s (got %d of %d bytes)", what, n, len(buf))
		}
		return msg, false, fmt.Errorf("%s: %w", what, err)
	}
	ne := binary.NativeEndian
	msg.Type = ne.Uint32(buf[0:])
	msg.Arg0 = ne.Uint32(buf[4:])
	msg.Arg1 = ne.Uint32(buf[8:])
	msg.Arg2 = ne.Uint32(buf[12:])
	return msg, true, nil
}

func (s *nsexec) writeSync(fd int, typ uint32, what string) error {
	buf := make([]byte, syncMsgSize)
	binary.NativeEndian.PutUint32(buf, typ)
	if err := writeAll(fd, buf); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

// childError converts an error reported by stage-1 or stage-2 to an error.
func (s *nsexec) childError(stage string, msg syncMsg) error {
	errno := unix.Errno(msg.Arg0)
	switch msg.Arg1 {
	case stepSyncWrite:
		return fmt.Errorf("%s: failed to sync with parent: write(%#x): %w", stage, msg.Arg2, errno)
	case stepSyncRead:
		return fmt.Errorf("%s: failed to sync with parent: read(%#x): %w", stage, msg.Arg2, errno)
	case stepSyncUnexpected:
		return fmt.Errorf("%s: failed to sync with parent: unexpected sync value %#x", stage, msg.Arg2)
	case stepChdir:
		return &os.PathError{Op: "chdir", Path: s.cfg.Dir, Err: errno}
	case stepSetns:
		name := "unknown"
		if int(msg.Arg2) < len(s.ns) {
			name = s.ns[msg.Arg2].name
		}
		return fmt.Errorf("failed to setns into %s namespace: %w", name, errno)
	case stepJoinNamespaces:
		var (
			failed uintptr
			errs   []error
		)
		for i, ns := range s.ns {
			if msg.Arg2&(1<<uint(i)) == 0 {
				failed |= ns.typ
				errs = append(errs, fmt.Errorf("failed to setns(%#x) into %s namespace (with path %s): %w",
					ns.typ, ns.name, ns.path, unix.EPERM))
			}
		}
		errs = append(errs, fmt.Errorf("failed to join {%s} namespaces: %w", nssetToStr(failed), errno))
		return errors.Join(errs...)
	case stepSetresuidUserns:
		return fmt.Errorf("failed to become root in user namespace: %w", errno)
	case stepUnshareUserns:
		return fmt.Errorf("failed to unshare user namespace: %w", errno)
	case stepSetDumpable:
		return fmt.Errorf("failed to set process as dumpable=%d: %w", msg.Arg2, errno)
	case stepUnshare:
		return fmt.Errorf("failed to unshare remaining namespaces: %w", errno)
	case stepCloneStage2:
		return fmt.Errorf("unable to spawn stage-2: %w", errno)
	case stepSetsid:
		return fmt.Errorf("setsid failed: %w", errno)
	case stepSetuid:
		return fmt.Errorf("setuid failed: %w", errno)
	case stepSetgid:
		return fmt.Errorf("setgid failed: %w", errno)
	case stepSetgroups:
		return fmt.Errorf("setgroups failed: %w", errno)
	case stepDup:
		return fmt.Errorf("failed to set up stage-2 file descriptors: %w", errno)
	case stepSetrlimit:
		return fmt.Errorf("failed to restore RLIMIT_NOFILE: %w", errno)
	case stepNondumpable:
		return fmt.Errorf("unable to make sure runc init is non-dumpable after execve "+
			"(no_new_privs or SECURE_NOROOT are set, and there's no second gid mapped): %w", errno)
	case stepExec:
		return fmt.Errorf("failed to execute runc init: %w", errno)
	}
	return fmt.Errorf("%s: unknown error (step %d): %w", stage, msg.Arg1, errno)
}

// Exec spawns stage-1, which joins and creates namespaces and spawns stage-2.
// Stage-1 and stage-2 are created with a raw clone(2) and only do raw system
// calls (the Go runtime cannot be used in a forked child of a multi-threaded
// process). Stage-2 does the final setup and executes runc init via
// execveat(2), which then runs the Go part of the container initialization in
// the new namespaces.
//
// Exec reaps stage-1 and returns the *os.Process for stage-2 (runc init).
func (c *Config) Exec() (_ *os.Process, retErr error) {
	s := &nsexec{
		cfg:            c,
		mntnsFd:        -1,
		ownExeFd:       -1,
		syncChild:      [2]int{-1, -1},
		syncGrandchild: [2]int{-1, -1},
		stage1Pid:      -1,
		stage2Pid:      -1,
	}
	defer func() {
		s.cleanup(retErr != nil)
		runtime.KeepAlive(c)
	}()

	logrus.Debug("nsexec: => nsexec container setup")

	// Log initial CPU affinity, this is solely for the tests in
	// ../../tests/integration/cpu_affinity.bats.
	logCPUAffinity()

	nonDumpable := len(c.Namespaces) > 0
	if nonDumpable {
		if err := s.openNamespaces(c.Namespaces); err != nil {
			return nil, err
		}
	}

	// Stage-2 executes the runc binary. If we joined an existing mount
	// namespace (the container's one) before that, the kernel would look
	// up the ELF interpreter of a dynamically linked binary (and then the
	// interpreter would load shared libraries) in it. Not only this does
	// not work, it must never be allowed to, since the files there are
	// controlled by the container. So, the existing mount namespace is
	// joined by the executed runc init instead (see stage2Init).
	//
	// Note that creating a new mount namespace (unshare(CLONE_NEWNS)) is
	// fine, as it is a copy of the current one.
	for i, ns := range s.ns {
		if ns.typ == unix.CLONE_NEWNS {
			s.mntnsFd = ns.fd
			s.ns = append(s.ns[:i], s.ns[i+1:]...)
			break
		}
	}

	emptyPath, _ := unix.BytePtrFromString("")
	stage1Name, _ := unix.BytePtrFromString("runc:[1:CHILD]")
	stage2Name, _ := unix.BytePtrFromString("runc:[2:INIT]")

	a := &childArgs{
		cloneFlags:  uint32ToUintptr(uint32(c.CloneFlags)) &^ unix.CLONE_NEWUSER,
		newUserns:   c.CloneFlags&unix.CLONE_NEWUSER != 0,
		nonDumpable: nonDumpable,
		timens:      c.TimeOffsets != "",
		setgroups:   !c.RootlessEUID && c.Setgroups,
		nondumpGid:  s.nondumpGid(),
		emptyPath:   emptyPath,
		stage1Name:  stage1Name,
		stage2Name:  stage2Name,
	}
	if c.Dir != "" {
		dirPtr, err := unix.BytePtrFromString(c.Dir)
		if err != nil {
			return nil, fmt.Errorf("invalid dir %q: %w", c.Dir, err)
		}
		a.dir = dirPtr
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
	if c.Exe != nil {
		a.exeFd = int(c.Exe.Fd())
	} else {
		exeFd, err := unix.Open("/proc/self/exe", unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to open /proc/self/exe: %w", err)
		}
		s.ownExeFd = exeFd
		a.exeFd = exeFd
	}

	args := c.Args
	if len(args) == 0 {
		args = os.Args
	}
	var err error
	a.argv, err = syscall.SlicePtrFromStrings(args)
	if err != nil {
		return nil, fmt.Errorf("invalid argv: %w", err)
	}

	var env []string
	if c.Env != nil {
		env = slices.Clone(c.Env)
	} else {
		env = os.Environ()
	}
	dumpVal := "0"
	if nonDumpable {
		dumpVal = "1"
	}
	env = append(env, stage2Env+"="+dumpVal)

	// Set up the file descriptors to pass to stage-2.
	stdinFd := 0
	if c.Stdin != nil {
		stdinFd = int(c.Stdin.Fd())
	}
	stdoutFd := 1
	if c.Stdout != nil {
		stdoutFd = int(c.Stdout.Fd())
	}
	stderrFd := 2
	if c.Stderr != nil {
		stderrFd = int(c.Stderr.Fd())
	}
	files := make([]int, 0, 3+len(c.ExtraFiles)+1)
	files = append(files, stdinFd, stdoutFd, stderrFd)
	for _, f := range c.ExtraFiles {
		files = append(files, int(f.Fd()))
	}
	if s.mntnsFd >= 0 {
		mntnsChildFd := len(files)
		files = append(files, s.mntnsFd)
		env = append(env, mntnsEnv+"="+strconv.Itoa(mntnsChildFd))
	}

	// If execve(2) regains a capability (see prepareNondumpExec), the
	// kernel clears some personality flags, so pass it to be restored.
	if pers, _, errno := unix.RawSyscall(unix.SYS_PERSONALITY, 0xffffffff, 0, 0); errno == 0 {
		env = append(env, personalityEnv+"="+strconv.FormatUint(uint64(pers), 10))
	}
	if c.Pdeathsig > 0 {
		env = append(env, pdeathsigEnv+"="+strconv.Itoa(int(c.Pdeathsig)))
	}
	a.envv, err = syscall.SlicePtrFromStrings(env)
	if err != nil {
		return nil, fmt.Errorf("invalid environment: %w", err)
	}

	// Socket pairs to sync with the child and grandchild.
	childPair, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to setup sync pipe between parent and child: %w", err)
	}
	s.syncChild = [2]int{childPair[0], childPair[1]}
	grandchildPair, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to setup sync pipe between parent and grandchild: %w", err)
	}
	s.syncGrandchild = [2]int{grandchildPair[0], grandchildPair[1]}
	a.syncChild = s.syncChild
	a.syncGrandchild = s.syncGrandchild

	nextFd := len(files)
	for _, fd := range files {
		if fd > nextFd {
			nextFd = fd
		}
	}
	if a.syncGrandchild[0] > nextFd {
		nextFd = a.syncGrandchild[0]
	}
	if a.exeFd > nextFd {
		nextFd = a.exeFd
	}
	a.files = files
	a.nextFd = nextFd + 1

	if c.UseCgroupFD {
		a.useClone3 = true
		a.clone3 = cloneArgs{
			flags:      unix.CLONE_INTO_CGROUP,
			exitSignal: uint64(unix.SIGCHLD),
			cgroup:     uint64(c.CgroupFD),
		}
	}

	logrus.Debug("nsexec: spawn stage-1")
	pid, errno := spawnChildren(a)
	if errno != 0 && a.useClone3 {
		logrus.Debugf("exec with CLONE_INTO_CGROUP failed: %v; retrying without", errno)
		c.UseCgroupFD = false
		a.useClone3 = false
		pid, errno = spawnChildren(a)
	}
	runtime.KeepAlive(a)
	if errno != 0 {
		return nil, fmt.Errorf("unable to spawn stage-1: %w", errno)
	}
	s.stage1Pid = int(pid)

	// Close the fds which are only used by the children.
	s.closeChildFds()

	// Configure oom_score_adj and cgroups/affinity/RDT on stage-1 while it
	// is still dumpable and in the host namespaces.
	if err := s.updateOomScoreAdj(s.stage1Pid); err != nil {
		return nil, err
	}
	if c.PrepareStage1 != nil {
		if err := c.PrepareStage1(s.stage1Pid); err != nil {
			return nil, err
		}
	}

	syncfd := s.syncChild[1]
	logrus.Debug("nsexec: -> stage-1 synchronisation loop")
	if err := s.writeSync(syncfd, syncStage1Start, "failed to sync with stage-1: write(SYNC_STAGE1_START)"); err != nil {
		return nil, err
	}
	for stage1Complete := false; !stage1Complete; {
		msg, ok, err := s.readSync(syncfd, "failed to sync with stage-1: next state")
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("failed to sync with stage-1: next state: unexpected EOF")
		}
		switch msg.Type {
		case syncUsermapPls:
			logrus.Debug("nsexec: stage-1 requested userns mappings")
			// Enable setgroups(2) if we've been asked to. But we also
			// have to explicitly disable setgroups(2) if we're creating
			// a rootless container for single-entry mapping (i.e.
			// Setgroups == false), this is required since Linux 3.19.
			if c.RootlessEUID && !c.Setgroups {
				if err := s.updateSetgroups(s.stage1Pid, "deny"); err != nil {
					return nil, err
				}
			}
			if err := s.updateIDMap("uid", c.UIDMapPath, s.stage1Pid, c.UIDMap); err != nil {
				return nil, err
			}
			if err := s.updateIDMap("gid", c.GIDMapPath, s.stage1Pid, c.GIDMap); err != nil {
				return nil, err
			}
			if err := s.writeSync(syncfd, syncUsermapAck, "failed to sync with stage-1: write(SYNC_USERMAP_ACK)"); err != nil {
				return nil, err
			}
		case syncRecvPidPls:
			logrus.Debug("nsexec: stage-1 requested pid to be forwarded")
			s.stage2Pid = int(int32(msg.Arg0))
			proc, err := os.FindProcess(s.stage2Pid)
			if err != nil {
				return nil, fmt.Errorf("failed to find stage-2 process %d: %w", s.stage2Pid, err)
			}
			s.stage2Proc = proc
			if err := s.writeSync(syncfd, syncRecvPidAck, "failed to sync with stage-1: write(SYNC_RECVPID_ACK)"); err != nil {
				return nil, err
			}
		case syncTimeOffsetsPls:
			logrus.Debug("nsexec: stage-1 requested timens offsets to be configured")
			if err := s.updateTimeNsOffsets(s.stage1Pid); err != nil {
				return nil, err
			}
			if err := s.writeSync(syncfd, syncTimeOffsetsAck, "failed to sync with child: write(SYNC_TIMEOFFSETS_ACK)"); err != nil {
				return nil, err
			}
		case syncChildFinish:
			logrus.Debug("nsexec: stage-1 complete")
			stage1Complete = true
			reapPid(s.stage1Pid)
			s.stage1Pid = -1
		case syncError:
			return nil, s.childError("stage-1", msg)
		default:
			return nil, fmt.Errorf("unexpected sync value from stage-1: %#x", msg.Type)
		}
	}
	logrus.Debug("nsexec: <- stage-1 synchronisation loop")

	// Now sync with grandchild (stage-2).
	closeFd(&s.syncChild[1])
	syncfd = s.syncGrandchild[1]

	logrus.Debug("nsexec: -> stage-2 synchronisation loop")
	logrus.Debug("nsexec: signalling stage-2 to run")
	if err := s.writeSync(syncfd, syncGrandchild, "failed to sync with child: write(SYNC_GRANDCHILD)"); err != nil {
		return nil, err
	}
	msg, ok, err := s.readSync(syncfd, "failed to sync with child: next state")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("failed to sync with stage-2: unexpected EOF")
	}
	switch msg.Type {
	case syncChildFinish:
		switch msg.Arg0 {
		case nondumpCaps:
			logrus.Debug("nsexec: stage-2 will be non-dumpable after exec (capability regained)")
		case nondumpGid:
			logrus.Debug("nsexec: stage-2 will be non-dumpable after exec (real and effective gids differ)")
		default:
			logrus.Debug("nsexec: stage-2 will be dumpable after exec")
		}
	case syncError:
		return nil, s.childError("stage-2", msg)
	default:
		return nil, fmt.Errorf("unexpected sync value from stage-2: %#x", msg.Type)
	}
	// Stage-2 is about to execute runc init; the sync socket is O_CLOEXEC,
	// so we get EOF once it succeeded, or an error message otherwise.
	msg, ok, err = s.readSync(syncfd, "failed to sync with child: exec")
	if err != nil {
		return nil, err
	}
	if ok {
		if msg.Type == syncError {
			return nil, s.childError("stage-2", msg)
		}
		return nil, fmt.Errorf("unexpected sync value from stage-2: %#x", msg.Type)
	}
	logrus.Debug("nsexec: stage-2 complete")
	logrus.Debug("nsexec: <- stage-2 synchronisation loop")
	logrus.Debug("nsexec: <= nsexec container setup")
	return s.stage2Proc, nil
}

func uint32ToUintptr(v uint32) uintptr {
	return uintptr(v)
}
