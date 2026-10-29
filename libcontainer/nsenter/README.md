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

The init function first gets the file descriptor number for the init pipe
from the environment variable `_LIBCONTAINER_INITPIPE` (which was opened by
the parent and kept open across the fork-exec of the `runc init` process).
If it is not set, this is not `runc init`, and nothing is done. Otherwise,
it goes through these stages:

* **stage-0** (normal Go code) reads the bootstrap data (namespace paths,
  clone flags, uid and gid mappings, etc.) from the init pipe, sets
  `oom_score_adj`, makes the process non-dumpable, opens the namespace
  files, and spawns stage-1 using `clone(CLONE_PARENT)`. It then serves
  the requests from stage-1 (writing the uid/gid maps and time namespace
  offsets), sends the PIDs of stage-1 and stage-2 to the runc parent, and
  exits.

* **stage-1** (raw system calls only) joins the namespaces (`setns(2)`),
  unshares the user namespace (asking stage-0 to set up the mappings),
  unshares the remaining namespaces, and spawns stage-2 using
  `clone(CLONE_PARENT)` (we have to fork to enter the new PID namespace).
  It then sends the stage-2 PID to stage-0 and exits.

* **stage-2** (raw system calls only) waits for stage-0, calls `setsid(2)`,
  becomes root, restores the original `RLIMIT_NOFILE` soft limit (changed by
  the Go runtime of stage-0, see `internal/nofile`), makes sure the process
  is not dumpable after `execve(2)` (see below), and re-executes the runc
  binary (`execveat(2)` on an `O_PATH` descriptor of `/proc/self/exe`,
  opened by stage-0) with `_LIBCONTAINER_NSEXEC_DONE` set in the
  environment.

* When the re-executed `runc init` sees `_LIBCONTAINER_NSEXEC_DONE`, the
  init function restores the dumpable flag, the real gid, and the
  personality, and returns to allow the Go part of `runc init` to take over.

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
