//go:build 386 || arm

package nsenter

import "golang.org/x/sys/unix"

// On 386 and arm, the 16-bit uid/gid syscalls are the legacy ones.
const (
	sysSetresuid = unix.SYS_SETRESUID32
	sysSetresgid = unix.SYS_SETRESGID32
	sysSetgroups = unix.SYS_SETGROUPS32
)
