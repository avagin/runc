// Package nofile records the RLIMIT_NOFILE soft limit the process was started
// with, before the Go runtime has a chance to change it.
//
// The syscall package raises the RLIMIT_NOFILE soft limit to the hard limit
// in its init function, and only restores the original value in children
// started via syscall.ForkExec or syscall.Exec. libcontainer/nsenter spawns
// the container init using a raw clone(2) followed by execveat(2), so it has
// to restore the original value by itself.
//
// This package must not import anything but "unsafe" (directly or
// indirectly). Per the Go specification, packages are initialized in import
// path order among those whose dependencies are already initialized, so a
// package without dependencies whose path sorts before "syscall" is
// guaranteed to be initialized before syscall's init raises the limit.
package nofile

import (
	_ "unsafe" // for go:linkname
)

type rlimit struct {
	Cur uint64
	Max uint64
}

// prlimit is pushed by the syscall package via go:linkname
// (golang.org/x/sys/unix uses it, too).
//
//go:linkname prlimit syscall.prlimit
func prlimit(pid int, resource int, newlimit *rlimit, old *rlimit) error

var (
	// Cur and Max are the original RLIMIT_NOFILE values.
	Cur, Max uint64
	// Valid is true if Cur and Max were successfully obtained.
	Valid bool
)

func init() {
	var lim rlimit
	if err := prlimit(0, rlimitNofile, nil, &lim); err == nil {
		Cur, Max, Valid = lim.Cur, lim.Max, true
	}
}
