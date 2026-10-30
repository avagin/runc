// Code borrowed from Go's src/syscall/asm_linux_mips64x.s.

//go:build linux && (mips64 || mips64le)

#include "textflag.h"

// func rawVforkSyscall(trap, a1, a2, a3 uintptr) (r1, err uintptr)
TEXT ·rawVforkSyscall(SB),NOSPLIT|NOFRAME,$0-48
	MOVV	a1+8(FP), R4
	MOVV	a2+16(FP), R5
	MOVV	a3+24(FP), R6
	MOVV	R0, R7
	MOVV	R0, R8
	MOVV	R0, R9
	MOVV	trap+0(FP), R2	// syscall entry
	SYSCALL
	BEQ	R7, ok
	MOVV	$-1, R1
	MOVV	R1, r1+32(FP)	// r1
	MOVV	R2, err+40(FP)	// errno
	RET
ok:
	MOVV	R2, r1+32(FP)	// r1
	MOVV	R0, err+40(FP)	// errno
	RET
