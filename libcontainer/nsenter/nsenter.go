//go:build linux

// Package nsenter implements the namespace creation and joining logic of runc.
//
// Config.Exec spawns a child process ("runc init") inside the configured
// container namespaces. Importing this package also registers an init function
// which runs in the newly executed "runc init" to finish the namespace setup.
// See README.md for details.
package nsenter

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	// stage2Env is set for the executed runc init (stage-2), so that
	// the package init function knows it is running inside stage-2. Its
	// value is "1" if the process has to be kept non-dumpable, and "0"
	// otherwise.
	stage2Env = "_LIBCONTAINER_NSEXEC_DONE"

	// personalityEnv is set to the parent's personality(2), to be restored
	// by stage-2.
	personalityEnv = "_LIBCONTAINER_NSEXEC_PERSONALITY"

	// pdeathsigEnv is set to the parent death signal, to be set by stage-2.
	pdeathsigEnv = "_LIBCONTAINER_NSEXEC_PDEATHSIG"

	// mntnsEnv is set to the file descriptor number of the (existing)
	// mount namespace to be joined by stage-2.
	mntnsEnv = "_LIBCONTAINER_NSEXEC_MNTNS"
)

// execDumpable is the value of the dumpable flag of the executed runc init
// right after execveat(2). Used by tests.
var execDumpable = -1

func init() {
	if v, ok := os.LookupEnv(stage2Env); ok {
		stage2Init(v)
	}
}

// stage2Init restores the process state altered in order to make sure that
// the process is not dumpable after execveat(2) (see prepareNondumpExec),
// and joins the existing mount namespace if any.
func stage2Init(dumpable string) {
	execDumpable, _ = unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	_ = os.Unsetenv(stage2Env)

	joinMntns()

	// Same as nsexec.c used to do, only keep the process non-dumpable if
	// any namespaces were joined.
	val := 0
	if dumpable == "0" {
		val = 1
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, uintptr(val), 0, 0, 0); err != nil {
		bail("failed to set process dumpable flag to %d: %v", val, err)
	}

	// Restore the real gid.
	if gid, egid := unix.Getgid(), unix.Getegid(); gid != egid {
		if err := unix.Setresgid(egid, -1, -1); err != nil {
			bail("failed to restore the real gid: %v", err)
		}
	}

	// Restore the personality.
	if str, ok := os.LookupEnv(personalityEnv); ok {
		_ = os.Unsetenv(personalityEnv)
		pers, err := strconv.ParseUint(str, 10, 32)
		if err != nil {
			bail("unable to parse %s=%s", personalityEnv, str)
		}
		cur, _, errno := unix.RawSyscall(unix.SYS_PERSONALITY, 0xffffffff, 0, 0)
		if errno == 0 && cur != uintptr(pers) {
			if _, _, errno := unix.RawSyscall(unix.SYS_PERSONALITY, uintptr(pers), 0, 0); errno != 0 {
				bail("failed to restore personality %#x: %v", pers, errno)
			}
		}
	}

	// Set the parent death signal (after Setresgid, which clears it).
	if str, ok := os.LookupEnv(pdeathsigEnv); ok {
		_ = os.Unsetenv(pdeathsigEnv)
		sig, err := strconv.Atoi(str)
		if err != nil || sig <= 0 {
			bail("unable to parse %s=%s", pdeathsigEnv, str)
		}
		if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(sig), 0, 0, 0); err != nil {
			bail("failed to set pdeath signal %d: %v", sig, err)
		}
	}
}

// joinMntns joins the container's (existing) mount namespace, if needed. See
// the comment about mntnsFd in Config.Exec.
//
// A multi-threaded process can not join a mount namespace (setns fails with
// EINVAL, since all the Go runtime threads share fs_struct). Instead, the
// current thread is locked, unshares its fs_struct, and joins the mount
// namespace alone. Other threads (if any) remain in the original mount
// namespace, so the rest of runc init must run on this thread, which is
// already the case (see libcontainer.Init). Upon execve(2) of the container
// process from this thread, the kernel kills all other threads, and the
// mount namespace and fs_struct of this thread are kept.
//
// This is called from a package init function, i.e. from the main goroutine
// which is locked to the main thread during package initialization. It is
// kept locked, so no other goroutine can run on this thread, and the thread
// is not reused in case the main goroutine exits.
func joinMntns() {
	str, ok := os.LookupEnv(mntnsEnv)
	if !ok {
		return
	}
	_ = os.Unsetenv(mntnsEnv)
	fd, err := strconv.Atoi(str)
	if err != nil || fd < 0 {
		bail("unable to parse %s=%s", mntnsEnv, str)
	}
	// Never unlocked.
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		bail("failed to unshare fs_struct: %v", err)
	}
	if err := unix.Setns(fd, unix.CLONE_NEWNS); err != nil {
		bail("failed to setns into mnt namespace: %v", err)
	}
	_ = unix.Close(fd)
}

// bail logs a fatal message to _LIBCONTAINER_LOGPIPE (or stderr, if not set)
// and terminates the stage-2 process.
func bail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if s := os.Getenv("_LIBCONTAINER_LOGPIPE"); s != "" {
		if fd, err := strconv.Atoi(s); err == nil && fd >= 0 {
			data, err := json.Marshal(struct {
				Level string `json:"level"`
				Msg   string `json:"msg"`
			}{"fatal", msg})
			if err == nil {
				_ = writeAll(fd, append(data, '\n'))
				unix.Exit(1)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "FATAL: %s\n", msg)
	unix.Exit(1)
}
