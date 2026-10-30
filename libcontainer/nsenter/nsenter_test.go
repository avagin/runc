package nsenter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/runc/libcontainer/nsenter/internal/nofile"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func TestNsenterValidPaths(t *testing.T) {
	cfg := &Config{
		Args:       []string{"nsenter-exec"},
		CloneFlags: unix.CLONE_NEWNET,
		Namespaces: []string{
			// join pid ns of the current process
			fmt.Sprintf("pid:/proc/%d/ns/pid", os.Getpid()),
		},
	}

	proc, err := cfg.Exec()
	if err != nil {
		t.Fatalf("nsenter failed: %v", err)
	}
	state, err := proc.Wait()
	if err != nil {
		t.Fatalf("wait failed: %v", err)
	}
	if !state.Success() {
		t.Fatalf("stage-2 exited with %v", state)
	}
}

func TestNsenterInvalidPaths(t *testing.T) {
	cfg := &Config{
		Args:       []string{"nsenter-exec"},
		CloneFlags: unix.CLONE_NEWNET,
		Namespaces: []string{
			fmt.Sprintf("pid:/proc/%d/ns/pid", -1),
		},
	}

	if proc, err := cfg.Exec(); err == nil {
		_ = proc.Kill()
		_, _ = proc.Wait()
		t.Fatal("expected error for invalid namespace path, got nil")
	}
}

func TestNsenterIncorrectPathType(t *testing.T) {
	cfg := &Config{
		Args:       []string{"nsenter-exec"},
		CloneFlags: unix.CLONE_NEWNET,
		Namespaces: []string{
			fmt.Sprintf("net:/proc/%d/ns/pid", os.Getpid()),
		},
	}

	if proc, err := cfg.Exec(); err == nil {
		_ = proc.Kill()
		_, _ = proc.Wait()
		t.Fatal("expected error for incorrect namespace type, got nil")
	}
}

func TestNsenterChildLogging(t *testing.T) {
	var buf bytes.Buffer
	origOut := logrus.StandardLogger().Out
	origLevel := logrus.GetLevel()
	logrus.SetOutput(&buf)
	logrus.SetLevel(logrus.DebugLevel)
	t.Cleanup(func() {
		logrus.SetOutput(origOut)
		logrus.SetLevel(origLevel)
	})

	cfg := &Config{
		Args:       []string{"nsenter-exec"},
		CloneFlags: unix.CLONE_NEWNET,
		Namespaces: []string{
			fmt.Sprintf("pid:/proc/%d/ns/pid", os.Getpid()),
		},
	}

	proc, err := cfg.Exec()
	if err != nil {
		t.Fatalf("nsenter failed: %v", err)
	}
	if _, err := proc.Wait(); err != nil {
		t.Fatalf("wait failed: %v", err)
	}
	if !strings.Contains(buf.String(), "nsexec container setup") {
		t.Fatalf("expected nsexec debug logs, got: %q", buf.String())
	}
}

// stage2Report is sent by the executed (stage-2) test binary.
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
		r.Env = os.Getenv(stage2Env) + os.Getenv(personalityEnv) + os.Getenv(pdeathsigEnv)
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
// (by the executed runc init).
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
	cfg := &Config{
		Args:       []string{"nsenter-report"},
		ExtraFiles: []*os.File{child},
		Namespaces: []string{"mnt:" + target},
	}
	proc, err := cfg.Exec()
	child.Close()
	if err != nil {
		t.Fatalf("nsenter error: %v", err)
	}

	var rep stage2Report
	if err := json.NewDecoder(parent).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if _, err := proc.Wait(); err != nil {
		t.Fatal(err)
	}
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

// TestNsenterStage2 checks the environment of the executed runc init.
func TestNsenterStage2(t *testing.T) {
	parent, child := newPipe(t)

	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Max < 1000 {
		t.Skip("RLIMIT_NOFILE hard limit is too low")
	}
	const softLimit = 512
	origNofileCur := nofile.Cur
	nofile.Cur = softLimit
	t.Cleanup(func() {
		nofile.Cur = origNofileCur
	})

	uid := os.Getuid()
	cfg := &Config{
		Args:         []string{"nsenter-report"},
		ExtraFiles:   []*os.File{child},
		CloneFlags:   unix.CLONE_NEWNET | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS,
		UIDMap:       fmt.Sprintf("0 %d 1\n", uid),
		GIDMap:       fmt.Sprintf("0 %d 1\n", os.Getgid()),
		RootlessEUID: true,
	}
	proc, err := cfg.Exec()
	child.Close()
	if err != nil {
		t.Fatalf("nsenter error: %v", err)
	}

	var rep stage2Report
	if err := json.NewDecoder(parent).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if _, err := proc.Wait(); err != nil {
		t.Fatal(err)
	}
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

// TestNsenterStage2Dumpable checks that the executed runc init
// is non-dumpable when joining namespaces.
func TestNsenterStage2Dumpable(t *testing.T) {
	parent, child := newPipe(t)
	cfg := &Config{
		Args:       []string{"nsenter-report"},
		ExtraFiles: []*os.File{child},
		Namespaces: []string{fmt.Sprintf("net:/proc/%d/ns/net", os.Getpid())},
	}
	proc, err := cfg.Exec()
	child.Close()
	if err != nil {
		t.Fatalf("nsenter error: %v", err)
	}

	var rep stage2Report
	if err := json.NewDecoder(parent).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if _, err := proc.Wait(); err != nil {
		t.Fatal(err)
	}
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
	cfg := &Config{
		Args:       []string{"nsenter-report"},
		ExtraFiles: []*os.File{child},
		Namespaces: []string{fmt.Sprintf("net:/proc/%d/ns/net", os.Getpid())},
	}

	type result struct {
		proc *os.Process
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		// Lock this OS thread and omit UnlockOSThread so the thread
		// (with no_new_privs set) is terminated when the goroutine exits.
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			ch <- result{err: err}
			return
		}
		proc, err := cfg.Exec()
		ch <- result{proc: proc, err: err}
	}()
	res := <-ch
	child.Close()
	if res.err != nil {
		t.Logf("nsenter error: %v", res.err)
		if !strings.Contains(res.err.Error(), "unable to make sure runc init is non-dumpable") {
			t.Fatalf("unexpected error: %v", res.err)
		}
		return
	}

	var rep stage2Report
	if err := json.NewDecoder(parent).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if _, err := res.proc.Wait(); err != nil {
		t.Fatal(err)
	}
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
