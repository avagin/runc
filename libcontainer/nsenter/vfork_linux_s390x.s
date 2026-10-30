// Code borrowed from Go's src/syscall/asm_linux_s390x.s.

#include "textflag.h"

// func rawVforkSyscall(trap, a1, a2, a3 uintptr) (r1, err uintptr)
TEXT ·rawVforkSyscall(SB),NOSPLIT|NOFRAME,$0-48
	MOVD	a1+8(FP), R2
	MOVD	a2+16(FP), R3
	MOVD	a3+24(FP), R4
	MOVD	$0, R5
	MOVD	$0, R6
	MOVD	$0, R7
	MOVD	trap+0(FP), R1	// syscall entry
	SYSCALL
	MOVD	$0xfffffffffffff001, R8
	CMPUBLT	R2, R8, ok2
	MOVD	$-1, r1+32(FP)
	NEG	R2, R2
	MOVD	R2, err+40(FP)	// errno
	RET
ok2:
	MOVD	R2, r1+32(FP)
	MOVD	$0, err+40(FP)	// errno
	RET
