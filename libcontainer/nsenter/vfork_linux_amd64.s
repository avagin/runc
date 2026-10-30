// Code borrowed from Go's src/syscall/asm_linux_amd64.s.

#include "textflag.h"

// func rawVforkSyscall(trap, a1, a2, a3 uintptr) (r1, err uintptr)
TEXT ·rawVforkSyscall(SB),NOSPLIT|NOFRAME,$0-48
	MOVQ	a1+8(FP), DI
	MOVQ	a2+16(FP), SI
	MOVQ	a3+24(FP), DX
	MOVQ	$0, R10
	MOVQ	$0, R8
	MOVQ	$0, R9
	MOVQ	trap+0(FP), AX	// syscall entry
	POPQ	R12 // preserve return address
	SYSCALL
	PUSHQ	R12
	CMPQ	AX, $0xfffffffffffff001
	JLS	ok2
	MOVQ	$-1, r1+32(FP)
	NEGQ	AX
	MOVQ	AX, err+40(FP)
	RET
ok2:
	MOVQ	AX, r1+32(FP)
	MOVQ	$0, err+40(FP)
	RET
