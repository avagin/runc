//go:build linux

// Package nsenter implements the namespace creation and joining logic of runc.
//
// Importing this package registers an init function which, if the process is
// a "runc init" (i.e. _LIBCONTAINER_INITPIPE is set), sets up the container
// namespaces and re-executes the binary in them. See README.md for details.
package nsenter

import (
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

// personalityEnv is set by stage-0 to its personality(2), to be restored
// by the re-executed runc init.
const personalityEnv = "_LIBCONTAINER_NSEXEC_PERSONALITY"

// mntnsEnv is set by stage-0 to the number of a file descriptor of the
// (existing) mount namespace to be joined by the re-executed runc init.
const mntnsEnv = "_LIBCONTAINER_NSEXEC_MNTNS"

// execDumpable is the value of the dumpable flag of the re-executed runc
// init right after execve(2). Used by tests.
var execDumpable = -1

func init() {
	setupLog()

	// Get the init pipe fd from the environment. The init pipe is used to
	// read the bootstrap data and tell the parent what the new pids are
	// after the setup is done.
	pipenum := envInt("_LIBCONTAINER_INITPIPE")
	if pipenum < 0 {
		// We are not a runc init. Just return to go runtime.
		return
	}

	if v, ok := os.LookupEnv(stage2Env); ok {
		// We are stage-2, re-executed by stage-0. Namespaces are set up.
		stage2Init(v)
		return
	}

	// Stage-0. This never returns.
	nsexec(pipenum)
}

// stage2Init restores the process state altered in order to make sure that
// the process is not dumpable after execve(2) (see prepareNondumpExec).
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
}

// joinMntns joins the container's (existing) mount namespace, if needed. See
// the comment about mntnsFd in nsexec.
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
