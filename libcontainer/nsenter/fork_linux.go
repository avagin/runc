package nsenter

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// These functions are implemented in the runtime package and are used by
// syscall.forkAndExecInChild. See also gvisor's pkg/sentry/platform/ptrace.

//go:linkname beforeFork syscall.runtime_BeforeFork
func beforeFork()

//go:linkname afterFork syscall.runtime_AfterFork
func afterFork()

//go:linkname afterForkInChild syscall.runtime_AfterForkInChild
func afterForkInChild()

func rawVforkSyscall(trap, a1, a2, a3 uintptr) (r1 uintptr, err syscall.Errno)

// Synchronisation values. The values are the same as in former nsexec.c.
const (
	syncStage1OOM      = 0x3e // Tell stage-1 that oom_score_adj has been written.
	syncStage1Start    = 0x3f // Tell stage-1 that PrepareStage1 has finished.
	syncUsermapPls     = 0x40 // Request parent to map our users.
	syncUsermapAck     = 0x41 // Mapping finished by the parent.
	syncRecvPidPls     = 0x42 // Tell parent we're sending the PID.
	syncStage1Ready    = 0x45 // Stage-1 is ready for PrepareStage1.
	syncTimeOffsetsPls = 0x46 // Request parent to write timens offsets.
	syncTimeOffsetsAck = 0x47 // Timens offsets were written.
	syncErrorStage1    = 0x48 // Stage-1 has failed.
	syncErrorStage2    = 0x49 // Stage-2 has failed.
)

// Error steps, sent by stage-1 or stage-2 along with syncError.
const (
	stepNone = iota
	stepSyncWrite
	stepSyncRead
	stepSyncUnexpected
	stepChdir
	stepSetns
	stepJoinNamespaces
	stepSetresuidUserns
	stepUnshareUserns
	stepSetDumpable
	stepUnshare
	stepCloneStage2
	stepSetsid
	stepSetuid
	stepSetgid
	stepSetgroups
	stepDup
	stepSetrlimit
	stepNondumpable
	stepExec
)

// How stage-2 ensures that the process is not dumpable right after execveat
// (reported to the parent along with syncChildFinish).
const (
	nondumpNone = iota // Not needed (or not possible, if not required).
	nondumpCaps        // A capability is regained on exec.
	nondumpGid         // The real and effective gids differ.
)

// syncMsg is a fixed-size message used for all synchronisation between
// the parent, stage-1, and stage-2.
type syncMsg struct {
	Type uint32
	Arg0 uint32 // pid, errno, or received sync type
	Arg1 uint32 // error step
	Arg2 uint32 // step-specific argument
}

const syncMsgSize = unsafe.Sizeof(syncMsg{})

type rlimit64 struct {
	Cur uint64
	Max uint64
}

// cloneArgs holds arguments for the clone3(2) Linux syscall.
type cloneArgs struct {
	flags      uint64
	pidFD      uint64
	childTID   uint64
	parentTID  uint64
	exitSignal uint64
	stack      uint64
	stackSize  uint64
	tls        uint64
	setTID     uint64
	setTIDSize uint64
	cgroup     uint64
}

// childArgs contains everything stage-1 and stage-2 need. It is fully
// prepared by the parent before the fork, because the forked children are not
// allowed to allocate memory.
type childArgs struct {
	// Whether to use clone3(2) (for CLONE_INTO_CGROUP) when spawning stage-1.
	useClone3 bool
	clone3    cloneArgs

	// Whether to use CLONE_VM | CLONE_VFORK when spawning stage-1 / stage-2.
	vforkStage1 bool
	vforkStage2 bool

	// syncSock[0] is used by stage-1 and stage-2, syncSock[1] by the parent.
	syncSock [2]int

	// Whether stage-1 must wait for syncStage1OOM before PR_SET_DUMPABLE(0) / CLONE_NEWUSER.
	waitOOM bool
	// Whether stage-1 must wait for syncStage1Start before CLONE_NEWCGROUP and cloning stage-2.
	waitPrep bool

	// Working directory to chdir(2) into in stage-1 before setns/unshare, or nil.
	dir *byte

	// Namespaces to join (pre-opened by the parent).
	nsFds      []int
	nsTypes    []uintptr
	cgroupNsFd int

	// Namespaces to create, except CLONE_NEWUSER and CLONE_NEWCGROUP.
	cloneFlags uintptr
	// Whether to create a new user namespace.
	newUserns bool
	// Whether to create a new cgroup namespace.
	newCgroupns bool
	// Whether the child process should be made non-dumpable (because
	// existing namespaces are being joined).
	nonDumpable bool
	// Whether to ask the parent to write time namespace offsets.
	timens bool

	// Whether to call setgroups(0, NULL) in stage-2.
	setgroups bool
	// Original RLIMIT_NOFILE to be restored in stage-2 before execveat.
	restoreNofile bool
	nofile        rlimit64

	// A gid (other than 0) valid in the container user namespace, to be
	// used as a real gid for execveat if the capability-based method is
	// not available, or -1.
	nondumpGid int

	// File descriptors to be placed at 0 .. len(files)-1 in stage-2.
	files  []int
	nextFd int

	// execveat(2) arguments for stage-2.
	exeFd     int
	argv      []*byte
	envv      []*byte
	emptyPath *byte

	// Process names (PR_SET_NAME), NUL-terminated.
	stage1Name *byte
	stage2Name *byte
}

const (
	linuxCapabilityVersion3 = 0x20080522
	secureNoroot            = 0 // From linux/securebits.h.
)

type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

// prepareNondumpExec makes sure the process executed by the following
// execve(2) is not dumpable from the very start, so there is no window
// during which the processes in the container could ptrace it or access
// its /proc/<pid> files (and thus the file descriptors it inherits from
// the runc parent).
//
// Normally, execve(2) makes the process dumpable (unless it executes a
// setuid/setgid binary, or the binary is not readable), meaning prctl(2)
// in the new program would come too late. However, the kernel sets the
// dumpable flag to suid_dumpable (which is never SUID_DUMP_USER) in two
// cases (see begin_new_exec and commit_creds):
//
//  1. The new credentials have permitted capabilities which the old ones
//     did not have. As stage-2 is root (in its user namespace), its
//     permitted set after execve(2) is the bounding set. So, if we drop a
//     capability from the permitted set (keeping it in the bounding set),
//     execve(2) regains it, and the process becomes non-dumpable. This
//     does not work if no_new_privs or SECURE_NOROOT are set.
//
//  2. The real and effective uids or gids differ at the time of execve(2).
//     This requires a second gid mapped in the user namespace.
//
// The executed runc init restores the real gid and the dumpable flag.
//
//go:nosplit
//go:norace
func prepareNondumpExec(a *childArgs) (mode uint32, err syscall.Errno) {
	var (
		hdr  capHeader
		data [2]capData
		r1   uintptr
		bit  uint32
		cap  int
	)
	nnp, _, _ := syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0)
	secbits, _, _ := syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_SECUREBITS, 0, 0, 0, 0, 0)
	if nnp == 0 && secbits&(1<<secureNoroot) == 0 {
		hdr.version = linuxCapabilityVersion3
		_, _, err = syscall.RawSyscall(unix.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0)
		if err != 0 {
			return nondumpNone, err
		}
		// Find a capability in both permitted and bounding sets. Start
		// from the highest one, to avoid touching the most commonly used
		// ones (such as CAP_DAC_OVERRIDE) which execve(2) might need.
		for cap = 63; cap >= 0; cap-- {
			bit = 1 << uint(cap&31)
			if data[cap>>5].permitted&bit == 0 {
				continue
			}
			r1, _, err = syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_CAPBSET_READ, uintptr(cap), 0, 0, 0, 0)
			if err == 0 && r1 == 1 {
				break
			}
		}
		if cap >= 0 {
			data[cap>>5].permitted &^= bit
			data[cap>>5].effective &^= bit
			_, _, err = syscall.RawSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0)
			if err != 0 {
				return nondumpNone, err
			}
			return nondumpCaps, 0
		}
	}
	if a.nondumpGid > 0 {
		_, _, err = syscall.RawSyscall(sysSetresgid, uintptr(a.nondumpGid), 0, 0)
		if err == 0 {
			return nondumpGid, 0
		}
	}
	if a.nonDumpable {
		if err == 0 {
			err = syscall.EPERM
		}
		return nondumpNone, err
	}
	return nondumpNone, 0
}

// childWrite sends a sync message. It is called from the forked children,
// so it must be nosplit and must not allocate.
//
//go:nosplit
//go:norace
func childWrite(fd int, typ, a0, a1, a2 uint32) syscall.Errno {
	msg := syncMsg{Type: typ, Arg0: a0, Arg1: a1, Arg2: a2}
	n, _, err := syscall.RawSyscall(unix.SYS_WRITE, uintptr(fd), uintptr(unsafe.Pointer(&msg)), syncMsgSize)
	if err == 0 && n != syncMsgSize {
		err = syscall.EIO
	}
	return err
}

// childRead receives a sync message, expecting the given type.
//
//go:nosplit
//go:norace
func childRead(fd int, want uint32, pid uintptr) {
	var msg syncMsg
	n, _, err := syscall.RawSyscall(unix.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&msg)), syncMsgSize)
	if err != 0 {
		childFail(fd, syncErrorStage1, stepSyncRead, err, want, pid)
	}
	if n != syncMsgSize {
		childFail(fd, syncErrorStage1, stepSyncRead, syscall.EIO, want, pid)
	}
	if msg.Type != want {
		childFail(fd, syncErrorStage1, stepSyncUnexpected, 0, msg.Type, pid)
	}
}

// childSend is like childWrite, but terminates the process on error.
//
//go:nosplit
//go:norace
func childSend(fd int, errType, typ, a0 uint32, pid uintptr) {
	if err := childWrite(fd, typ, a0, 0, 0); err != 0 {
		childFail(fd, errType, stepSyncWrite, err, typ, pid)
	}
}

// childFail reports an error to the parent, kills the given pid (if non-zero),
// and terminates the process.
//
//go:nosplit
//go:norace
func childFail(fd int, errType, step uint32, errno syscall.Errno, arg uint32, pid uintptr) {
	if pid != 0 {
		syscall.RawSyscall(unix.SYS_KILL, pid, uintptr(syscall.SIGKILL), 0)
	}
	_ = childWrite(fd, errType, uint32(errno), step, arg)
	for {
		syscall.RawSyscall(unix.SYS_EXIT_GROUP, 1, 0, 0)
	}
}

//go:nosplit
//go:norace
func childExit(code uintptr) {
	for {
		syscall.RawSyscall(unix.SYS_EXIT_GROUP, code, 0, 0)
	}
}

// tryUnshare calls unshare(2), retrying on EINVAL. Kernels prior to v4.3 may
// return EINVAL on unshare when another process reads runc's /proc/$PID/status
// or /proc/$PID/maps.
//
//go:nosplit
//go:norace
func tryUnshare(flags uintptr) syscall.Errno {
	var err syscall.Errno
	for i := 0; i < 5; i++ {
		_, _, err = syscall.RawSyscall(unix.SYS_UNSHARE, flags, 0, 0)
		if err != syscall.EINVAL {
			break
		}
	}
	return err
}

// spawnChildren forks stage-1 (which, in turn, forks stage-2) and returns
// the stage-1 pid in the parent.
//
// In the children, this function must not acquire any locks, because they
// might have been locked at the time of the fork. This means no rescheduling,
// no malloc calls, no write barriers, and no new stack segments (the runtime
// will throw if the stack needs to grow). Only nosplit functions and raw
// system calls can be used. For the same reason the compiler does not race
// instrument it. The children never return from this function: stage-1 exits,
// and stage-2 executes the runc binary via execveat(2).
//
//go:noinline
//go:norace
//go:nocheckptr
func spawnChildren(a *childArgs) (pid uintptr, errno syscall.Errno) {
	var origDumpable uintptr
	if a.vforkStage1 && a.nonDumpable {
		origDumpable, _, _ = syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
	}

	pid, errno = spawnStage1(a)
	if a.vforkStage1 && a.nonDumpable && origDumpable == 1 {
		syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 1, 0, 0, 0, 0)
	}
	afterFork()
	return
}

// spawnStage1 is separated from spawnChildren so that the parent and stage-1
// do not share the same active stack frame when CLONE_VFORK is used.
//
//go:noinline
//go:norace
//go:nocheckptr
func spawnStage1(a *childArgs) (pid uintptr, errno syscall.Errno) {
	// Declare all variables at the top, so that there's no need for any
	// allocation after beforeFork.
	var (
		err1    syscall.Errno
		i       int
		pass    int
		toJoin  uintptr
		joined  uintptr
		allow   uintptr
		done    uint64
		allDone uint64
		stage2  uintptr
		sfd     int
		flags   uintptr
	)

	// About to call fork. No more allocation or calls
	// of non-nosplit functions. This also blocks all signals.
	beforeFork()
	if a.useClone3 {
		if a.vforkStage1 {
			a.clone3.flags |= unix.CLONE_VM | unix.CLONE_VFORK
		}
		pid, errno = rawVforkSyscall(unix.SYS_CLONE3, uintptr(unsafe.Pointer(&a.clone3)), unsafe.Sizeof(a.clone3), 0)
	} else {
		flags = uintptr(syscall.SIGCHLD)
		if a.vforkStage1 {
			flags |= unix.CLONE_VM | unix.CLONE_VFORK
		}
		if runtime.GOARCH == "s390x" {
			// On Linux/s390, the first two arguments of clone(2) are swapped.
			pid, errno = rawVforkSyscall(unix.SYS_CLONE, 0, flags, 0)
		} else {
			pid, errno = rawVforkSyscall(unix.SYS_CLONE, flags, 0, 0)
		}
	}
	if errno != 0 || pid != 0 {
		// In the parent, return immediately so we do not share the
		// stack frame with the child when using vfork.
		return
	}

	// ----- Stage-1 -----
	//
	// Our job is to join any provided namespaces and unshare all of the
	// requested namespaces. If we've been asked to CLONE_NEWUSER, we ask
	// our parent to set up our user mappings for us. Then, we create a new
	// child (stage-2) with CLONE_PARENT for PID namespace, and send its
	// PID to our parent.
	sfd = a.syncSock[0]
	syscall.RawSyscall(unix.SYS_CLOSE, uintptr(a.syncSock[1]), 0, 0)
	syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_SET_NAME, uintptr(unsafe.Pointer(a.stage1Name)), 0, 0, 0, 0)

	// Wait for the parent to write oom_score_adj while we are still
	// dumpable and in the host user namespace.
	if a.waitOOM {
		childRead(sfd, syncStage1OOM, 0)
	}

	if a.dir != nil {
		if _, _, err1 = syscall.RawSyscall(unix.SYS_CHDIR, uintptr(unsafe.Pointer(a.dir)), 0, 0); err1 != 0 {
			childFail(sfd, syncErrorStage1, stepChdir, err1, 0, 0)
		}
	}

	// Make the process non-dumpable before joining namespaces, to avoid
	// race conditions that could allow processes in namespaces we're
	// joining to access host resources.
	if a.nonDumpable {
		if _, _, err1 = syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 0, 0, 0, 0, 0); err1 != 0 {
			childFail(sfd, syncErrorStage1, stepSetDumpable, err1, 0, 0)
		}
	}

	// We need to setns first. We cannot do this earlier (in the parent)
	// because of the fact that we forked to get here (the PID of stage-2
	// would be meaningless).
	if len(a.nsFds) > 0 {
		for i = 0; i < len(a.nsTypes); i++ {
			toJoin |= a.nsTypes[i]
			allDone |= 1 << uint(i)
		}
		// We first try to join all non-userns namespaces to join any
		// namespaces that we might not be able to join once we switch
		// credentials to the container's userns. We then join the user
		// namespace, and then try to join any remaining namespaces (this
		// last step is needed for rootless containers -- we don't get
		// setns(2) permissions until we join the userns and get
		// CAP_SYS_ADMIN). This is similar to what nsenter(1) does.
		for pass = 0; pass < 3; pass++ {
			if pass == 1 {
				allow = unix.CLONE_NEWUSER
			} else {
				allow = toJoin &^ (joined | unix.CLONE_NEWUSER)
			}
			for i = 0; i < len(a.nsFds); i++ {
				if done&(1<<uint(i)) != 0 || a.nsTypes[i]&allow == 0 {
					continue
				}
				_, _, err1 = syscall.RawSyscall(unix.SYS_SETNS, uintptr(a.nsFds[i]), a.nsTypes[i], 0)
				if err1 == syscall.EPERM {
					// Skip permission errors (see above).
					continue
				}
				if err1 != 0 {
					childFail(sfd, syncErrorStage1, stepSetns, err1, uint32(i), 0)
				}
				joined |= a.nsTypes[i]
				done |= 1 << uint(i)

				// If we change user namespaces, make sure we switch to
				// root in the namespace (this matches the logic for
				// unshare(CLONE_NEWUSER)), lots of things can break if we
				// aren't the right user. See
				// https://github.com/opencontainers/runc/issues/4466.
				if a.nsTypes[i] == unix.CLONE_NEWUSER {
					if _, _, err1 = syscall.RawSyscall(sysSetresuid, 0, 0, 0); err1 != 0 {
						childFail(sfd, syncErrorStage1, stepSetresuidUserns, err1, 0, 0)
					}
				}
				syscall.RawSyscall(unix.SYS_CLOSE, uintptr(a.nsFds[i]), 0, 0)
			}
		}
		// Make sure we joined all the namespaces we planned to.
		if done != allDone {
			childFail(sfd, syncErrorStage1, stepJoinNamespaces, syscall.EPERM, uint32(done), 0)
		}
	}

	// Deal with user namespaces first. They are quite special, as they
	// affect our ability to unshare other namespaces and are used as
	// context for privilege checks.
	//
	// We don't unshare all namespaces in one go. The reason for this is
	// that, while the kernel documentation may claim otherwise, there are
	// certain cases where unsharing all namespaces at once will result in
	// namespace objects being owned incorrectly (for example, the SELinux
	// label of the internal kern-mount that mqueue uses will be incorrect
	// if the UTS namespace is cloned before the USER namespace is mapped).
	if a.newUserns {
		if err1 = tryUnshare(unix.CLONE_NEWUSER); err1 != 0 {
			childFail(sfd, syncErrorStage1, stepUnshareUserns, err1, 0, 0)
		}
		// We need to set ourselves as dumpable temporarily so that the
		// parent process can write to our procfs files.
		if a.nonDumpable {
			if _, _, err1 = syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 1, 0, 0, 0, 0); err1 != 0 {
				childFail(sfd, syncErrorStage1, stepSetDumpable, err1, 1, 0)
			}
		}
		// We don't have the privileges to do any mapping here, so
		// signal the parent to do the mapping for us.
		childSend(sfd, syncErrorStage1, syncUsermapPls, 0, 0)
		childRead(sfd, syncUsermapAck, 0)
		// Revert temporary re-dumpable setting.
		if a.nonDumpable {
			if _, _, err1 = syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 0, 0, 0, 0, 0); err1 != 0 {
				childFail(sfd, syncErrorStage1, stepSetDumpable, err1, 0, 0)
			}
		}
		// Become root in the namespace proper.
		if _, _, err1 = syscall.RawSyscall(sysSetresuid, 0, 0, 0); err1 != 0 {
			childFail(sfd, syncErrorStage1, stepSetresuidUserns, err1, 0, 0)
		}
	}

	// Unshare all of the remaining namespaces (except cgroupns, which must
	// wait for PrepareStage1). Note that we don't merge this with clone()
	// because there were some old kernel versions where
	// clone(CLONE_PARENT | CLONE_NEWPID) was broken.
	if a.cloneFlags != 0 {
		if err1 = tryUnshare(a.cloneFlags); err1 != 0 {
			childFail(sfd, syncErrorStage1, stepUnshare, err1, 0, 0)
		}
	}

	if a.timens {
		childSend(sfd, syncErrorStage1, syncTimeOffsetsPls, 0, 0)
		childRead(sfd, syncTimeOffsetsAck, 0)
	}

	// Wait for the parent to finish PrepareStage1 (configuring cgroups,
	// CPU affinity, and Intel RDT) before unsharing/joining cgroupns and
	// cloning stage-2.
	if a.waitPrep {
		if a.newUserns || a.timens {
			childSend(sfd, syncErrorStage1, syncStage1Ready, 0, 0)
		}
		childRead(sfd, syncStage1Start, 0)
	}

	if a.cgroupNsFd >= 0 {
		if _, _, err1 = syscall.RawSyscall(unix.SYS_SETNS, uintptr(a.cgroupNsFd), unix.CLONE_NEWCGROUP, 0); err1 != 0 {
			childFail(sfd, syncErrorStage1, stepSetns, err1, uint32(len(a.nsFds)), 0)
		}
		syscall.RawSyscall(unix.SYS_CLOSE, uintptr(a.cgroupNsFd), 0, 0)
	}
	if a.newCgroupns {
		if err1 = tryUnshare(unix.CLONE_NEWCGROUP); err1 != 0 {
			childFail(sfd, syncErrorStage1, stepUnshare, err1, 0, 0)
		}
	}

	// We fork again because of PID namespace, setns(2) or unshare(2) don't
	// change the PID namespace of the calling process, so we must fork to
	// actually enter the new PID namespace. We use CLONE_PARENT so that
	// stage-2 is a direct child of the parent process.
	stage2, err1 = spawnStage2(a)
	if err1 != 0 {
		childFail(sfd, syncErrorStage1, stepCloneStage2, err1, 0, 0)
	}
	// Send the child PID to our parent.
	childSend(a.syncSock[0], syncErrorStage1, syncRecvPidPls, uint32(stage2), stage2)
	// Our work is done. Stage-2 is doing the rest of the work.
	childExit(0)
	return
}

// spawnStage2 is separated from spawnStage1 so that stage-1 and stage-2
// do not share the same active stack frame when CLONE_VFORK is used.
//
//go:noinline
//go:nosplit
//go:norace
//go:nocheckptr
func spawnStage2(a *childArgs) (pid uintptr, errno syscall.Errno) {
	var (
		err1   syscall.Errno
		i      int
		sfd    int
		exeFd  int
		nextfd int
		flags  uintptr
	)

	flags = unix.CLONE_PARENT | uintptr(syscall.SIGCHLD)
	if a.vforkStage2 {
		flags |= unix.CLONE_VM | unix.CLONE_VFORK
	}
	if runtime.GOARCH == "s390x" {
		// On Linux/s390, the first two arguments of clone(2) are swapped.
		pid, errno = rawVforkSyscall(unix.SYS_CLONE, 0, flags, 0)
	} else {
		pid, errno = rawVforkSyscall(unix.SYS_CLONE, flags, 0, 0)
	}
	if errno != 0 || pid != 0 {
		// In stage-1, return immediately so we do not share the
		// stack frame with stage-2 when using vfork.
		return
	}

	// ----- Stage-2 -----
	//
	// We're the final child process. Our job is to do the final setup
	// steps and then execute runc init in the new namespaces.
	sfd = a.syncSock[0]
	exeFd = a.exeFd
	syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_SET_NAME, uintptr(unsafe.Pointer(a.stage2Name)), 0, 0, 0, 0)

	if _, _, err1 = syscall.RawSyscall(unix.SYS_SETSID, 0, 0, 0); err1 != 0 {
		childFail(sfd, syncErrorStage2, stepSetsid, err1, 0, 0)
	}
	if _, _, err1 = syscall.RawSyscall(sysSetresuid, 0, 0, 0); err1 != 0 {
		childFail(sfd, syncErrorStage2, stepSetuid, err1, 0, 0)
	}
	if _, _, err1 = syscall.RawSyscall(sysSetresgid, 0, 0, 0); err1 != 0 {
		childFail(sfd, syncErrorStage2, stepSetgid, err1, 0, 0)
	}
	if a.setgroups {
		if _, _, err1 = syscall.RawSyscall(sysSetgroups, 0, 0, 0); err1 != 0 {
			childFail(sfd, syncErrorStage2, stepSetgroups, err1, 0, 0)
		}
	}

	// Place the inherited file descriptors at 0 .. len(a.files)-1.
	// First, move sfd and exeFd above len(a.files) so pass 2 won't
	// overwrite them.
	nextfd = a.nextFd
	if sfd < len(a.files) {
		if _, _, err1 = syscall.RawSyscall(unix.SYS_DUP3, uintptr(sfd), uintptr(nextfd), unix.O_CLOEXEC); err1 != 0 {
			childFail(sfd, syncErrorStage2, stepDup, err1, 0, 0)
		}
		sfd = nextfd
		nextfd++
	}
	if exeFd < len(a.files) {
		if _, _, err1 = syscall.RawSyscall(unix.SYS_DUP3, uintptr(exeFd), uintptr(nextfd), unix.O_CLOEXEC); err1 != 0 {
			childFail(sfd, syncErrorStage2, stepDup, err1, 0, 0)
		}
		exeFd = nextfd
		nextfd++
	}
	// Pass 1: move any a.files[i] < i above nextfd so pass 2 won't
	// overwrite an fd it needs later.
	for i = 0; i < len(a.files); i++ {
		if a.files[i] >= 0 && a.files[i] < i {
			if _, _, err1 = syscall.RawSyscall(unix.SYS_DUP3, uintptr(a.files[i]), uintptr(nextfd), unix.O_CLOEXEC); err1 != 0 {
				childFail(sfd, syncErrorStage2, stepDup, err1, 0, 0)
			}
			a.files[i] = nextfd
			nextfd++
		}
	}
	// Pass 2: dup a.files[i] down onto i (clearing O_CLOEXEC).
	for i = 0; i < len(a.files); i++ {
		if a.files[i] < 0 {
			syscall.RawSyscall(unix.SYS_CLOSE, uintptr(i), 0, 0)
			continue
		}
		if a.files[i] == i {
			if _, _, err1 = syscall.RawSyscall(unix.SYS_FCNTL, uintptr(i), unix.F_SETFD, 0); err1 != 0 {
				childFail(sfd, syncErrorStage2, stepDup, err1, 0, 0)
			}
			continue
		}
		if _, _, err1 = syscall.RawSyscall(unix.SYS_DUP3, uintptr(a.files[i]), uintptr(i), 0); err1 != 0 {
			childFail(sfd, syncErrorStage2, stepDup, err1, 0, 0)
		}
	}
	// Mark any remaining fds >= len(a.files) as O_CLOEXEC.
	if len(a.files) > 0 {
		syscall.RawSyscall(unix.SYS_CLOSE_RANGE, uintptr(len(a.files)), ^uintptr(0), unix.CLOSE_RANGE_CLOEXEC)
	}

	// Restore the RLIMIT_NOFILE soft limit changed by the Go runtime of
	// the parent, so that the exec'ed runc init sees the original value.
	if a.restoreNofile {
		if _, _, err1 = syscall.RawSyscall6(unix.SYS_PRLIMIT64, 0, unix.RLIMIT_NOFILE, uintptr(unsafe.Pointer(&a.nofile)), 0, 0, 0); err1 != 0 {
			childFail(sfd, syncErrorStage2, stepSetrlimit, err1, 0, 0)
		}
	}

	// This must be the last thing to do before execveat, as it might drop
	// a capability.
	if _, err1 = prepareNondumpExec(a); err1 != 0 {
		childFail(sfd, syncErrorStage2, stepNondumpable, err1, 0, 0)
	}

	// Reset signal handlers to their defaults and restore the signal mask.
	afterForkInChild()

	// Execute runc init. sfd is O_CLOEXEC, so the parent gets EOF once
	// execveat succeeds.
	_, _, err1 = syscall.RawSyscall6(unix.SYS_EXECVEAT, uintptr(exeFd),
		uintptr(unsafe.Pointer(a.emptyPath)),
		uintptr(unsafe.Pointer(&a.argv[0])),
		uintptr(unsafe.Pointer(&a.envv[0])),
		unix.AT_EMPTY_PATH, 0)
	childFail(sfd, syncErrorStage2, stepExec, err1, 0, 0)
	return
}
