//go:build !386 && !arm

package nsenter

import "golang.org/x/sys/unix"

const (
	sysSetresuid = unix.SYS_SETRESUID
	sysSetresgid = unix.SYS_SETRESGID
	sysSetgroups = unix.SYS_SETGROUPS
)
