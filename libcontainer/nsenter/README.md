## nsenter

The `nsenter` package implements the early stage of `runc init`: it joins
the existing namespaces and creates the new ones requested by the container
configuration, before the Go part of the container initialization runs.

This used to be done by a C constructor (`nsexec.c`) which ran before the Go
runtime started. It is now implemented in pure Go, and no longer requires cgo.

The `nsenter` package registers an `init` function, which is run if the
package is imported. Therefore, you must `import` this library into a
package if you plan to use `libcontainer` directly:

```go
import _ "github.com/opencontainers/runc/libcontainer/nsenter"
```

### How it works

Some namespace operations (`setns(2)` into user and mount namespaces,
`unshare(CLONE_NEWUSER)`) require the calling process to be single-threaded,
which a Go program never is. Thus, the work is done in processes created by
a raw `clone(2)`. Such a process only has a single thread (the one that
called `clone`), but it can not use the Go runtime (it can not allocate
memory, grow its stack, or take locks), so it only uses raw system calls,
the same way `syscall.forkAndExecInChild` does. The runtime hooks used for
that are `syscall.runtime_BeforeFork`, `syscall.runtime_AfterFork`, and
`syscall.runtime_AfterForkInChild`.

The parent `runc` process invokes `nsenter.Config.Exec()` directly to spawn the
`runc init` process inside the container namespaces:

* **parent (`nsenter.Config.Exec`)** (normal Go code) opens the namespace
  files, spawns stage-1 using `clone(2)` (or `clone3(CLONE_INTO_CGROUP)`),
  sets stage-1's `oom_score_adj`, invokes `PrepareStage1` (so cgroups, CPU
  affinity, and Intel RDT can be configured while stage-1 is still in the
  host namespaces), serves the requests from stage-1 (writing the uid/gid maps
  and time namespace offsets), reaps stage-1, and returns the `*os.Process`
  for stage-2.

* **stage-1** (raw system calls only) waits for the parent to finish
  `PrepareStage1`, `chdir(2)`s to the container rootfs, makes the process
  non-dumpable, joins the namespaces (`setns(2)`), except for an existing
  mount namespace (see below), unshares the user namespace (asking the parent
  to set up the mappings), unshares the remaining namespaces, and spawns
  stage-2 using `clone(CLONE_PARENT)` (we have to fork to enter the new PID
  namespace, and `CLONE_PARENT` makes stage-2 a direct child of the parent
  `runc`). It then sends the stage-2 PID to the parent and exits.

* **stage-2** (raw system calls only) waits for the parent, calls `setsid(2)`,
  becomes root, sets up the inherited file descriptors (`0..N-1`) and marks
  all higher file descriptors `O_CLOEXEC` via `close_range(CLOSE_RANGE_CLOEXEC)`,
  restores the original `RLIMIT_NOFILE` soft limit (changed by the Go runtime
  of the parent, see `internal/nofile`), makes sure the process is not dumpable
  after `execve(2)` (see below), and executes `runc init` (`execveat(2)` on an
  `O_PATH` descriptor of the cloned `/proc/self/exe` binary) with
  `_LIBCONTAINER_NSEXEC_DONE` set in the environment.

* When the executed `runc init` sees `_LIBCONTAINER_NSEXEC_DONE`, the
  `nsenter` package init function joins the existing mount namespace (if any),
  restores the dumpable flag, the real gid, the personality, and the parent
  death signal (`PR_SET_PDEATHSIG`), and returns to allow the Go part of
  `runc init` to take over.

### Joining an existing mount namespace

Stage-2 must not execute `runc init` while being in the container's mount
namespace: for a dynamically linked binary, the kernel would look up the ELF
interpreter (which would then load the shared libraries) in the container
filesystem. Instead, the parent passes the mount namespace fd to `runc init`
(via `_LIBCONTAINER_NSEXEC_MNTNS`), which joins it from the package init
function.

A multi-threaded process can't `setns(2)` into a mount namespace, since all
the Go runtime threads share the same `fs_struct`. So, the main thread
(on which the main goroutine runs during the package initialization) is
locked (and is never unlocked), unshares its `fs_struct`
(`unshare(CLONE_FS)`), and joins the mount namespace alone. The rest of
`runc init` runs on this thread (see `libcontainer.Init`), and when it
`execve(2)`s the container process, the kernel kills all other threads,
and the mount namespace of this thread is kept.

Creating a new mount namespace (`unshare(CLONE_NEWNS)`) is still done by
stage-1, as it starts as a copy of the current one.

### Dumpability across execve

The process must never be dumpable while it is in the container namespaces
and holds the file descriptors inherited from the runc parent. A plain
`execve(2)` makes the process dumpable, and any `prctl(PR_SET_DUMPABLE, 0)`
in the new program would come too late. So, right before `execveat(2)`,
stage-2 relies on one of the two cases in which the kernel sets the dumpable
flag to `suid_dumpable` instead (see `begin_new_exec` and `commit_creds`):

1. The new credentials gain permitted capabilities. Since stage-2 is root
   (in its user namespace), `execve(2)` sets its permitted set to the
   bounding set, so stage-2 drops one capability which is in the bounding
   set from its permitted set, and the exec regains it. This does not work
   if `no_new_privs` or `SECURE_NOROOT` is set.
2. The real and effective gids differ. This requires a second gid to be
   mapped in the container user namespace.

If neither is possible and namespaces are being joined, runc init fails.

NOTE: We do both `setns(2)` and `clone(2)` even if we don't have any
`CLONE_NEW*` clone flags because we must fork a new process in order to
enter the PID namespace.
