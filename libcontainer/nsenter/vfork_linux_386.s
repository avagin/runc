// Code borrowed from Go's src/syscall/asm_linux_386.s.

#include "textflag.h"

// func rawVforkSyscall(trap, a1, a2, a3 uintptr) (r1, err uintptr)
TEXT ·rawVforkSyscall(SB),NOSPLIT|NOFRAME,$0-24
	MOVL	trap+0(FP), AX	// syscall entry
	MOVL	a1+4(FP), BX
	MOVL	a2+8(FP), CX
	MOVL	a3+12(FP), DX
	POPL	SI // preserve return address
	INT	$0x80
	PUSHL	SI
	CMPL	AX, $0xfffff001
	JLS	ok
	MOVL	$-1, r1+16(FP)
	NEGL	AX
	MOVL	AX, err+20(FP)
	RET
ok:
	MOVL	AX, r1+16(FP)
	MOVL	$0, err+20(FP)
	RET
