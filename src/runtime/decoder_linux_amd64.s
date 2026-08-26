// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "go_asm.h"
#include "go_tls.h"
#include "funcdata.h"
#include "textflag.h"

// Trampolines for calling into the statically-linked XED-based decoder
// (inst_decode/lib/decoder.c, linked in via decoder_linux_amd64.syso).
// These are needed instead of ordinary cgo because decoderHandleSigprof
// runs on the gsignal stack inside a signal handler. Modeled on
// asancall<> in asan_amd64.s.

// func decoderInitCall()
TEXT runtime·decoderInitCall(SB), NOSPLIT, $0-0
	MOVQ	$decoder_init(SB), AX
	JMP	decodercall<>(SB)

// func decoderExtractMemAddrCall(instrAddr uint64, regs *decoderRegs, memOps *decoderMemOpInfo, outLen *uint32) uint32
TEXT runtime·decoderExtractMemAddrCall(SB), NOSPLIT, $0-36
	MOVQ	instrAddr+0(FP), DI
	MOVQ	regs+8(FP), SI
	MOVQ	memOps+16(FP), DX
	MOVQ	outLen+24(FP), CX
	MOVQ	$extract_mem_addr(SB), AX
	CALL	decodercall<>(SB)
	MOVL	AX, ret+32(FP)
	RET

// Switches SP to the g0 stack (unless already on g0 or gsignal) and calls
// the function whose address is in AX. Arguments are already loaded into
// DI/SI/DX/CX per the System V AMD64 ABI. On return AX holds the callee's
// return value and SP has been restored.
TEXT decodercall<>(SB), NOSPLIT, $0-0
	get_tls(R12)
	MOVQ	g(R12), R14
	MOVQ	SP, R12		// callee-saved, preserved across the CALL
	CMPQ	R14, $0
	JE	call	// no g; still on a system stack

	MOVQ	g_m(R14), R13

	// Switch to g0 stack if we aren't already on g0 or gsignal.
	MOVQ	m_gsignal(R13), R10
	CMPQ	R10, R14
	JE	call	// already on gsignal

	MOVQ	m_g0(R13), R10
	CMPQ	R10, R14
	JE	call	// already on g0

	MOVQ	(g_sched+gobuf_sp)(R10), SP
call:
	ANDQ	$~15, SP	// alignment for the C ABI
	CALL	AX
	MOVQ	R12, SP
	RET
