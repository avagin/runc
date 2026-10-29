package nsenter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/nsenter/internal/nofile"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func TestNsenterValidPaths(t *testing.T) {
	args := []string{"nsenter-exec"}
	parent, child := newPipe(t)

	namespaces := []string{
		// join pid ns of the current process
		fmt.Sprintf("pid:/proc/%d/ns/pid", os.Getpid()),
	}
	cmd := &exec.Cmd{
		Path:       os.Args[0],
		Args:       args,
		ExtraFiles: []*os.File{child},
		Env:        []string{"_LIBCONTAINER_INITPIPE=3"},
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("nsenter failed to start: %v", err)
	}
	child.Close()

	// write cloneFlags
	r := nl.NewNetlinkRequest(int(libcontainer.InitMsg), 0)
	r.AddData(&libcontainer.Int32msg{
		Type:  libcontainer.CloneFlagsAttr,
		Value: uint32(unix.CLONE_NEWNET),
	})
	r.AddData(&libcontainer.Bytemsg{
		Type:  libcontainer.NsPathsAttr,
		Value: []byte(strings.Join(namespaces, ",")),
	})
	if _, err := io.Copy(parent, bytes.NewReader(r.Serialize())); err != nil {
		t.Fatal(err)
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("nsenter error: %v", err)
	}

	reapChildren(t, parent)
}

func TestNsenterInvalidPaths(t *testing.T) {
	args := []string{"nsenter-exec"}
	parent, child := newPipe(t)

	namespaces := []string{
		fmt.Sprintf("pid:/proc/%d/ns/pid", -1),
	}
	cmd := &exec.Cmd{
		Path:       os.Args[0],
		Args:       args,
		ExtraFiles: []*os.File{child},
		Env:        []string{"_LIBCONTAINER_INITPIPE=3"},
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("nsenter failed to start: %v", err)
	}
	child.Close()

	// write cloneFlags
	r := nl.NewNetlinkRequest(int(libcontainer.InitMsg), 0)
	r.AddData(&libcontainer.Int32msg{
		Type:  libcontainer.CloneFlagsAttr,
		Value: uint32(unix.CLONE_NEWNET),
	})
	r.AddData(&libcontainer.Bytemsg{
		Type:  libcontainer.NsPathsAttr,
		Value: []byte(strings.Join(namespaces, ",")),
	})
	if _, err := io.Copy(parent, bytes.NewReader(r.Serialize())); err != nil {
		t.Fatal(err)
	}

	if err := cmd.Wait(); err == nil {
		t.Fatalf("nsenter exits with a zero exit status")
	}
}

func TestNsenterIncorrectPathType(t *testing.T) {
	args := []string{"nsenter-exec"}
	parent, child := newPipe(t)

	namespaces := []string{
		fmt.Sprintf("net:/proc/%d/ns/pid", os.Getpid()),
	}
	cmd := &exec.Cmd{
		Path:       os.Args[0],
		Args:       args,
		ExtraFiles: []*os.File{child},
		Env:        []string{"_LIBCONTAINER_INITPIPE=3"},
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("nsenter failed to start: %v", err)
	}
	child.Close()

	// write cloneFlags
	r := nl.NewNetlinkRequest(int(libcontainer.InitMsg), 0)
	r.AddData(&libcontainer.Int32msg{
		Type:  libcontainer.CloneFlagsAttr,
		Value: uint32(unix.CLONE_NEWNET),
	})
	r.AddData(&libcontainer.Bytemsg{
		Type:  libcontainer.NsPathsAttr,
		Value: []byte(strings.Join(namespaces, ",")),
	})
	if _, err := io.Copy(parent, bytes.NewReader(r.Serialize())); err != nil {
		t.Fatal(err)
	}

	if err := cmd.Wait(); err == nil {
		t.Fatalf("nsenter error: %v", err)
	}
}

func TestNsenterChildLogging(t *testing.T) {
	args := []string{"nsenter-exec"}
	parent, child := newPipe(t)
	logread, logwrite := newPipe(t)

	namespaces := []string{
		// join pid ns of the current process
		fmt.Sprintf("pid:/proc/%d/ns/pid", os.Getpid()),
	}
	cmd := &exec.Cmd{
		Path:       os.Args[0],
		Args:       args,
		ExtraFiles: []*os.File{child, logwrite},
		Env:        []string{"_LIBCONTAINER_INITPIPE=3", "_LIBCONTAINER_LOGPIPE=4"},
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("nsenter failed to start: %v", err)
	}
	child.Close()
	logwrite.Close()

	// write cloneFlags
	r := nl.NewNetlinkRequest(int(libcontainer.InitMsg), 0)
	r.AddData(&libcontainer.Int32msg{
		Type:  libcontainer.CloneFlagsAttr,
		Value: uint32(unix.CLONE_NEWNET),
	})
	r.AddData(&libcontainer.Bytemsg{
		Type:  libcontainer.NsPathsAttr,
		Value: []byte(strings.Join(namespaces, ",")),
	})
	if _, err := io.Copy(parent, bytes.NewReader(r.Serialize())); err != nil {
		t.Fatal(err)
	}

	getLogs(t, logread)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("nsenter error: %v", err)
	}

	reapChildren(t, parent)
}

// stage2Report is sent by the re-executed (stage-2) test binary.
type stage2Report struct {
	NetNs    string `json:"netns"`
	UserNs   string `json:"userns"`
	UtsNs    string `json:"utsns"`
	UIDMap   string `json:"uid_map"`
	UID      int    `json:"uid"`
	NofileC  uint64 `json:"nofile_cur"`
	Dumpable int    `json:"dumpable"`
	ExecDump int    `json:"exec_dumpable"`
	Gid      int    `json:"gid"`
	Egid     int    `json:"egid"`
	Env      string `json:"env"`
	Ppid     int    `json:"ppid"`
	MntNs    string `json:"mntns"`
	ThMntNs  string `json:"thread_mntns"`
	MainTh   bool   `json:"main_thread"`
}

func init() {
	if fd := os.Getenv("_TEST_NNP_INITPIPE"); fd != "" {
		// Set no_new_privs and re-execute as nsenter-report.
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			panic(err)
		}
		exe, _ := os.Executable()
		if err := unix.Exec(exe, []string{"nsenter-report"}, []string{"_LIBCONTAINER_INITPIPE=" + fd}); err != nil {
			panic(err)
		}
	}
	if os.Args[0] == "nsenter-report" {
		var r stage2Report
		r.NetNs, _ = os.Readlink("/proc/self/ns/net")
		r.UserNs, _ = os.Readlink("/proc/self/ns/user")
		r.UtsNs, _ = os.Readlink("/proc/self/ns/uts")
		m, _ := os.ReadFile("/proc/self/uid_map")
		r.UIDMap = strings.Join(strings.Fields(string(m)), " ")
		r.UID = os.Getuid()
		// The value the process was started with (before
		// the Go runtime raised it).
		r.NofileC = nofile.Cur
		r.Dumpable, _ = unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		r.ExecDump = execDumpable
		r.Gid, r.Egid = os.Getgid(), os.Getegid()
		r.Env = os.Getenv(stage2Env) + os.Getenv(personalityEnv)
		r.Ppid = os.Getppid()
		r.MntNs, _ = os.Readlink("/proc/self/ns/mnt")
		r.ThMntNs, _ = os.Readlink("/proc/thread-self/ns/mnt")
		r.MainTh = unix.Gettid() == os.Getpid()
		_ = json.NewEncoder(os.NewFile(3, "init")).Encode(r)
		unix.Exit(0)
	}
	if os.Args[0] == "nsenter-sleep" {
		time.Sleep(time.Minute)
		unix.Exit(0)
	}
	if strings.HasPrefix(os.Args[0], "nsenter-") {
		unix.Exit(0)
	}
}

// TestNsenterJoinMntns checks that an existing mount namespace is joined
// (by the re-executed runc init).
func TestNsenterJoinMntns(t *testing.T) {
	// A process holding a new mount namespace.
	holder := &exec.Cmd{
		Path:        os.Args[0],
		Args:        []string{"nsenter-sleep"},
		SysProcAttr: &unix.SysProcAttr{Unshareflags: unix.CLONE_NEWNS},
	}
	if err := holder.Start(); err != nil {
		t.Skipf("can't create a mount namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = holder.Process.Kill()
		_ = holder.Wait()
	})
	target := fmt.Sprintf("/proc/%d/ns/mnt", holder.Process.Pid)
	self, _ := os.Readlink("/proc/self/ns/mnt")
	// Wait for the unshare to happen.
	var want string
	for range 100 {
		want, _ = os.Readlink(target)
		if want != "" && want != self {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if want == "" || want == self {
		t.Fatalf("mount namespace was not created: %q", want)
	}

	parent, child := newPipe(t)
	cmd := &exec.Cmd{
		Path:       os.Args[0],
		Args:       []string{"nsenter-report"},
		ExtraFiles: []*os.File{child},
		Env:        []string{"_LIBCONTAINER_INITPIPE=3"},
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("nsenter failed to start: %v", err)
	}
	child.Close()

	r := nl.NewNetlinkRequest(int(libcontainer.InitMsg), 0)
	r.AddData(&libcontainer.Int32msg{
		Type:  libcontainer.CloneFlagsAttr,
		Value: 0,
	})
	r.AddData(&libcontainer.Bytemsg{
		Type:  libcontainer.NsPathsAttr,
		Value: []byte("mnt:" + target),
	})
	if _, err := io.Copy(parent, bytes.NewReader(r.Serialize())); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("nsenter error: %v", err)
	}
	dec := json.NewDecoder(parent)
	var pids struct {
		Pid2 int `json:"stage2_pid"`
		Pid1 int `json:"stage1_pid"`
	}
	if err := dec.Decode(&pids); err != nil {
		t.Fatal(err)
	}
	var rep stage2Report
	if err := dec.Decode(&rep); err != nil {
		t.Fatal(err)
	}
	_, _ = unix.Wait4(pids.Pid1, nil, 0, nil)
	_, _ = unix.Wait4(pids.Pid2, nil, 0, nil)
	t.Logf("report: %+v", rep)
	if !rep.MainTh {
		t.Errorf("not running on the main thread")
	}
	if rep.MntNs != want || rep.ThMntNs != want {
		t.Errorf("mount namespace: want %q, got %q (thread: %q)", want, rep.MntNs, rep.ThMntNs)
	}
	if rep.Dumpable != 0 || rep.ExecDump == 1 {
		t.Errorf("stage-2 is dumpable (after exec: %d, now: %d)", rep.ExecDump, rep.Dumpable)
	}
}

// TestNsenterStage2 checks the environment of the re-executed runc init.
func TestNsenterStage2(t *testing.T) {
	parent, child := newPipe(t)

	cmd := &exec.Cmd{
		Path:       os.Args[0],
		Args:       []string{"nsenter-report"},
		ExtraFiles: []*os.File{child},
		Env:        []string{"_LIBCONTAINER_INITPIPE=3"},
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	}
	// Use a low soft limit which the Go runtime of stage-0 raises.
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Max < 1000 {
		t.Skip("RLIMIT_NOFILE hard limit is too low")
	}
	const softLimit = 512
	orig := lim
	lim.Cur = softLimit
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	err := cmd.Start()
	_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &orig)
	if err != nil {
		t.Fatalf("nsenter failed to start: %v", err)
	}
	child.Close()

	uid := os.Getuid()
	r := nl.NewNetlinkRequest(int(libcontainer.InitMsg), 0)
	r.AddData(&libcontainer.Int32msg{
		Type:  libcontainer.CloneFlagsAttr,
		Value: uint32(unix.CLONE_NEWNET | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS),
	})
	r.AddData(&libcontainer.Bytemsg{
		Type:  libcontainer.UidmapAttr,
		Value: []byte(fmt.Sprintf("0 %d 1\n", uid)),
	})
	r.AddData(&libcontainer.Bytemsg{
		Type:  libcontainer.GidmapAttr,
		Value: []byte(fmt.Sprintf("0 %d 1\n", os.Getgid())),
	})
	r.AddData(&libcontainer.Boolmsg{
		Type:  libcontainer.RootlessEUIDAttr,
		Value: true,
	})
	if _, err := io.Copy(parent, bytes.NewReader(r.Serialize())); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("nsenter error: %v", err)
	}

	dec := json.NewDecoder(parent)
	var pids struct {
		Pid2 int `json:"stage2_pid"`
		Pid1 int `json:"stage1_pid"`
	}
	if err := dec.Decode(&pids); err != nil {
		t.Fatal(err)
	}
	var rep stage2Report
	if err := dec.Decode(&rep); err != nil {
		t.Fatal(err)
	}
	_, _ = unix.Wait4(pids.Pid1, nil, 0, nil)
	_, _ = unix.Wait4(pids.Pid2, nil, 0, nil)
	t.Logf("report: %+v", rep)

	for _, ns := range []struct{ name, got string }{
		{"net", rep.NetNs},
		{"user", rep.UserNs},
		{"uts", rep.UtsNs},
	} {
		self, _ := os.Readlink("/proc/self/ns/" + ns.name)
		if ns.got == "" || ns.got == self {
			t.Errorf("%s namespace was not created: %q", ns.name, ns.got)
		}
	}
	if want := fmt.Sprintf("0 %d 1", uid); rep.UIDMap != want {
		t.Errorf("uid_map: want %q, got %q", want, rep.UIDMap)
	}
	if rep.UID != 0 {
		t.Errorf("uid: want 0, got %d", rep.UID)
	}
	if rep.NofileC != softLimit {
		t.Errorf("RLIMIT_NOFILE soft limit: want %d, got %d", softLimit, rep.NofileC)
	}
	if rep.Env != "" {
		t.Errorf("%s or %s is not unset: %q", stage2Env, personalityEnv, rep.Env)
	}
	// No namespaces were joined, so the process is dumpable (same as
	// before), but should not be dumpable right after execve.
	if rep.ExecDump == 1 {
		t.Errorf("stage-2 is dumpable right after execve")
	}
	if rep.Dumpable != 1 {
		t.Errorf("stage-2 is not dumpable")
	}
	if rep.Gid != rep.Egid {
		t.Errorf("stage-2 real gid (%d) != effective gid (%d)", rep.Gid, rep.Egid)
	}
	if rep.Ppid != os.Getpid() {
		t.Errorf("stage-2 parent: want %d, got %d", os.Getpid(), rep.Ppid)
	}
}

// TestNsenterStage2Dumpable checks that the re-executed runc init
// is non-dumpable when joining namespaces.
func TestNsenterStage2Dumpable(t *testing.T) {
	parent, child := newPipe(t)
	cmd := &exec.Cmd{
		Path:       os.Args[0],
		Args:       []string{"nsenter-report"},
		ExtraFiles: []*os.File{child},
		Env:        []string{"_LIBCONTAINER_INITPIPE=3"},
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("nsenter failed to start: %v", err)
	}
	child.Close()

	r := nl.NewNetlinkRequest(int(libcontainer.InitMsg), 0)
	r.AddData(&libcontainer.Int32msg{
		Type:  libcontainer.CloneFlagsAttr,
		Value: 0,
	})
	r.AddData(&libcontainer.Bytemsg{
		Type:  libcontainer.NsPathsAttr,
		Value: []byte(fmt.Sprintf("net:/proc/%d/ns/net", os.Getpid())),
	})
	if _, err := io.Copy(parent, bytes.NewReader(r.Serialize())); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("nsenter error: %v", err)
	}
	dec := json.NewDecoder(parent)
	var pids struct {
		Pid2 int `json:"stage2_pid"`
		Pid1 int `json:"stage1_pid"`
	}
	if err := dec.Decode(&pids); err != nil {
		t.Fatal(err)
	}
	var rep stage2Report
	if err := dec.Decode(&rep); err != nil {
		t.Fatal(err)
	}
	_, _ = unix.Wait4(pids.Pid1, nil, 0, nil)
	_, _ = unix.Wait4(pids.Pid2, nil, 0, nil)
	if rep.Dumpable != 0 {
		t.Errorf("stage-2 is dumpable")
	}
	if rep.ExecDump == 1 {
		t.Errorf("stage-2 is dumpable right after execve")
	}
}

// TestNsenterNoNewPrivs checks that, with no_new_privs set (which prevents
// the capability-based method), stage-2 is either non-dumpable right after
// execve (using the gid-based method), or nsexec fails.
func TestNsenterNoNewPrivs(t *testing.T) {
	parent, child := newPipe(t)
	var stderr bytes.Buffer
	cmd := &exec.Cmd{
		Path:       os.Args[0],
		Args:       []string{"nsenter-nnp"},
		ExtraFiles: []*os.File{child},
		Env:        []string{"_TEST_NNP_INITPIPE=3"},
		Stdout:     os.Stdout,
		Stderr:     &stderr,
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("nsenter failed to start: %v", err)
	}
	child.Close()

	r := nl.NewNetlinkRequest(int(libcontainer.InitMsg), 0)
	r.AddData(&libcontainer.Int32msg{
		Type:  libcontainer.CloneFlagsAttr,
		Value: 0,
	})
	r.AddData(&libcontainer.Bytemsg{
		Type:  libcontainer.NsPathsAttr,
		Value: []byte(fmt.Sprintf("net:/proc/%d/ns/net", os.Getpid())),
	})
	if _, err := io.Copy(parent, bytes.NewReader(r.Serialize())); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Logf("nsenter error: %v, stderr: %s", err, stderr.String())
		if !strings.Contains(stderr.String(), "unable to make sure runc init is non-dumpable") {
			t.Fatal("unexpected error")
		}
		return
	}
	dec := json.NewDecoder(parent)
	var pids struct {
		Pid2 int `json:"stage2_pid"`
		Pid1 int `json:"stage1_pid"`
	}
	if err := dec.Decode(&pids); err != nil {
		t.Fatal(err)
	}
	var rep stage2Report
	if err := dec.Decode(&rep); err != nil {
		t.Fatal(err)
	}
	_, _ = unix.Wait4(pids.Pid1, nil, 0, nil)
	_, _ = unix.Wait4(pids.Pid2, nil, 0, nil)
	t.Logf("report: %+v", rep)
	if rep.ExecDump == 1 {
		t.Errorf("stage-2 is dumpable right after execve")
	}
	if rep.Dumpable != 0 {
		t.Errorf("stage-2 is dumpable")
	}
	if rep.Gid != rep.Egid {
		t.Errorf("stage-2 real gid (%d) != effective gid (%d)", rep.Gid, rep.Egid)
	}
}

func newPipe(t *testing.T) (parent, child *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("socketpair failed:", err)
	}
	parent = os.NewFile(uintptr(fds[1]), "parent")
	child = os.NewFile(uintptr(fds[0]), "child")
	t.Cleanup(func() {
		parent.Close()
		child.Close()
	})
	return parent, child
}

func reapChildren(t *testing.T, parent *os.File) {
	t.Helper()
	decoder := json.NewDecoder(parent)
	decoder.DisallowUnknownFields()
	var pid struct {
		Pid2 int `json:"stage2_pid"`
		Pid1 int `json:"stage1_pid"`
	}
	if err := decoder.Decode(&pid); err != nil {
		t.Fatal(err)
	}

	// Reap children.
	_, _ = unix.Wait4(pid.Pid1, nil, 0, nil)
	_, _ = unix.Wait4(pid.Pid2, nil, 0, nil)

	// Sanity check.
	if pid.Pid1 == 0 || pid.Pid2 == 0 {
		t.Fatal("got pids:", pid)
	}
}

func getLogs(t *testing.T, logread *os.File) {
	logsDecoder := json.NewDecoder(logread)
	logsDecoder.DisallowUnknownFields()
	var logentry struct {
		Level string `json:"level"`
		Msg   string `json:"msg"`
	}

	for {
		if err := logsDecoder.Decode(&logentry); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			t.Fatal("init log decoding error:", err)
		}
		t.Logf("logentry: %+v", logentry)
		if logentry.Level == "" || logentry.Msg == "" {
			t.Fatalf("init log: empty log entry: %+v", logentry)
		}
	}
}
