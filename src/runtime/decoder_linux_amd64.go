// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import "internal/runtime/atomic"

// decoderRegs mirrors regs_t in inst_decode/lib/decoder.h. Field order and
// widths must match the C struct exactly, since it is passed by pointer
// across the cgo_import_static call.
type decoderRegs struct {
	rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi uint64
	r8, r9, r10, r11, r12, r13, r14, r15   uint64
	rip                                    uint64
}

// decoderMemOpInfo mirrors mem_op_info_t in inst_decode/lib/decoder.h.
type decoderMemOpInfo struct {
	addr     uint64
	numBytes uint32
	isWrite  int32
}

const decoderMaxMemOps = 2 // matches MAX_MEM_OPS in decoder.h

// extract_mem_addr and decoder_init are defined in inst_decode/lib/decoder.c
// and statically linked in via decoder_linux_amd64.syso (built by
// inst_decode/Makefile against Intel XED). They are called through the
// asm trampolines below rather than cgo, since this code runs on the
// signal (gsignal) stack and must remain async-signal-safe.
//
//go:cgo_import_static extract_mem_addr
//go:cgo_import_static decoder_init

//go:noescape
func decoderInitCall()

//go:noescape
func decoderExtractMemAddrCall(instrAddr uint64, regs *decoderRegs, memOps *decoderMemOpInfo) uint32

var decoderReady atomic.Bool

// decoderInit initializes the XED decode tables. It must run once, before
// any SIGPROF-driven decode attempt, and is called from schedinit.
func decoderInit() {
	decoderInitCall()
	decoderReady.Store(true)
}

// decoderMemOpTableBits sizes the fixed, allocation-free table used to
// record decoded memory operands. SIGPROF fires on the gsignal stack
// concurrently with GC, so this table cannot grow dynamically.
const decoderMemOpTableBits = 13
const decoderMemOpTableSize = 1 << decoderMemOpTableBits
const decoderMemOpTableMask = decoderMemOpTableSize - 1

type decoderMemOpEntry struct {
	key   atomic.Uint64 // instruction address; 0 means empty
	op    decoderMemOpInfo
	ready atomic.Bool // entry is ready to be read
}

var decoderMemOpTable [decoderMemOpTableSize]decoderMemOpEntry
var decoderMemOpCount atomic.Uint32
var decoderMemOpDropped atomic.Uint32

//go:nosplit
func decoderHash(addr uint64) uint32 {
	// Fibonacci hashing, same technique used by racelite's temperature table.
	return uint32((addr * 0x9E3779B97F4A7C15) >> (64 - decoderMemOpTableBits))
}

// decoderRecordMemOp records the decoded memory operand for the instruction
// at instrAddr. Called from the SIGPROF path (which multiple threads can receive
// concurrently), so it must not allocate or take locks.
//
//go:nosplit
//go:nowritebarrierrec
func decoderRecordMemOp(instrAddr uint64, op *decoderMemOpInfo) {
	if instrAddr == 0 {
		return
	}
	var h uint32 = decoderHash(instrAddr)
	for i := uint32(0); i < decoderMemOpTableSize; i++ {
		// linear probling open address hash
		var e *decoderMemOpEntry = &decoderMemOpTable[(h+i)&decoderMemOpTableMask]
		var cur uint64 = e.key.Load()
		if cur == 0 && e.key.CompareAndSwap(0, instrAddr) {
			e.op = *op
			e.ready.Store(true)
			decoderMemOpCount.Add(1)
			return
		}
		// cur != 0 and no CAS performed || CAS failed
		if cur == instrAddr || e.key.Load() == instrAddr {
			// Already claimed by this instruction address; refresh the
			// recorded operand. This can race with a concurrent printer
			// reading e.op, or with another thread's SIGPROF handler
			// concurrently recording the same instrAddr and writing e.op
			// (last writer wins on op.addr, the only field that can differ
			// between racers). Both are acceptable for this best-effort,
			// statistics-only table.
			e.op = *op
			e.ready.Store(true)
			return
		}
	}
	decoderMemOpDropped.Add(1)
}

// decoderHandleSigprof is called from sighandler for every delivered
// SIGPROF, before the normal profiling sample is taken. It mirrors
// sigtrap_handler in inst_decode/test_decoder.c: decode the instruction the
// interrupted thread was about to execute and, if it is a real memory
// operand, record it.
//
//go:nosplit
//go:nowritebarrierrec
func decoderHandleSigprof(c *sigctxt) {
	if !decoderReady.Load() {
		return
	}

	var regs decoderRegs = decoderRegs{
		rax: c.rax(), rcx: c.rcx(), rdx: c.rdx(), rbx: c.rbx(),
		rsp: c.rsp(), rbp: c.rbp(), rsi: c.rsi(), rdi: c.rdi(),
		r8: c.r8(), r9: c.r9(), r10: c.r10(), r11: c.r11(),
		r12: c.r12(), r13: c.r13(), r14: c.r14(), r15: c.r15(),
		rip: c.rip(),
	}

	var memOps [decoderMaxMemOps]decoderMemOpInfo
	var n uint32 = decoderExtractMemAddrCall(regs.rip, &regs, &memOps[0])
	if n > decoderMaxMemOps {
		n = decoderMaxMemOps
	}
	for i := uint32(0); i < n; i++ {
		// XED reports address-generation-only instructions (e.g. leaq) as
		// memory operands with a zero size; those are not real accesses.
		if memOps[i].numBytes == 0 {
			continue
		}
		decoderRecordMemOp(regs.rip, &memOps[i])
	}
}

// decoderPrintMemOpTable dumps every recorded (instruction address -> memory
// operand) entry. Called once as the program exits so test programs can
// inspect what the SIGPROF path decoded over the run.
func decoderPrintMemOpTable() {
	if !decoderReady.Load() {
		return
	}
	print("decoder: ", decoderMemOpCount.Load(), " memory operand(s) recorded via SIGPROF")
	var d uint32 = decoderMemOpDropped.Load()
	if d > 0 {
		print(" (", d, " dropped, table full)")
	}
	print("\n")
	for i := range decoderMemOpTable {
		var e *decoderMemOpEntry = &decoderMemOpTable[i]
		if !e.ready.Load() {
			continue
		}
		var instrAddr uint64 = e.key.Load()
		var op decoderMemOpInfo = e.op
		print("decoder: instr=", hex(instrAddr), " addr=", hex(op.addr),
			" bytes=", op.numBytes, " write=", op.isWrite != 0, "\n")
	}
}
