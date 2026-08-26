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
func decoderExtractMemAddrCall(instrAddr uint64, regs *decoderRegs, memOps *decoderMemOpInfo, outLen *uint32) uint32

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
// Commented out: this was Step 1's testing/diagnostic scaffolding (dumped via
// decoderPrintMemOpTable below, also commented out) and isn't needed for Step 2's
// arm/detect path. Left in place, not deleted: decoderMemOpTable/decoderMemOpEntry/
// decoderHash below are still live and are a reasonable starting point if a future
// optimization needs to memoize part of a decoded instruction on the Go side (to
// reconstruct memory operand addresses without calling back into the decoder library).
//
// //go:nosplit
// //go:nowritebarrierrec
// func decoderRecordMemOp(instrAddr uint64, op *decoderMemOpInfo) {
// 	if instrAddr == 0 {
// 		return
// 	}
// 	var h uint32 = decoderHash(instrAddr)
// 	for i := uint32(0); i < decoderMemOpTableSize; i++ {
// 		// linear probling open address hash
// 		var e *decoderMemOpEntry = &decoderMemOpTable[(h+i)&decoderMemOpTableMask]
// 		var cur uint64 = e.key.Load()
// 		if cur == 0 && e.key.CompareAndSwap(0, instrAddr) {
// 			e.op = *op
// 			e.ready.Store(true)
// 			decoderMemOpCount.Add(1)
// 			return
// 		}
// 		// cur != 0 and no CAS performed || CAS failed
// 		if cur == instrAddr || e.key.Load() == instrAddr {
// 			// Already claimed by this instruction address; refresh the
// 			// recorded operand. This can race with a concurrent printer
// 			// reading e.op, or with another thread's SIGPROF handler
// 			// concurrently recording the same instrAddr and writing e.op
// 			// (last writer wins on op.addr, the only field that can differ
// 			// between racers). Both are acceptable for this best-effort,
// 			// statistics-only table.
// 			e.op = *op
// 			e.ready.Store(true)
// 			return
// 		}
// 	}
// 	decoderMemOpDropped.Add(1)
// }

// raceSampleSigprof is called from sighandler for every delivered SIGPROF, before the normal
// profiling sample is taken. It mirrors sigtrap_handler in inst_decode/test_decoder.c: decode
// the instruction the interrupted thread was about to execute, and for every real memory operand
// found (one for most instructions, two for movs/cmps-style instructions), both record it (as
// before) and drive the hardware-watchpoint race detector: capture this thread's own stack once,
// publish each real operand into its own activeWatchpoints slot, arm a watchpoint per operand on
// every other live thread — both operands concurrently in one shared round when there are two,
// not sequentially — sleep for a short configurable window, then disarm everything this call
// armed. See race_detector_plan.md for the full design.
//
// Deliberately not //go:nosplit: sigprof (called right after this, from the same _SIGPROF
// branch in sighandler) isn't nosplit either.  gsignal's stack is fixed-size (malg(32*1024),
// os_linux.go) and cannot grow at all; exceeding stack size causes a fatal crash, but we are
// ok here because this call chain's real stack usage comfortably fits within the fixed 32KB,
// The //go:nosplit's own static analysis exists to *guarantee* a call chain can never need
// to grow and has a much more conservative ~792-byte budget.
//
//go:nowritebarrierrec
func raceSampleSigprof(c *sigctxt, gp *g) {
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
	var decodedLen uint32 // unused on this path; see decodeAccessorDirection for why it matters there
	var n uint32 = decoderExtractMemAddrCall(regs.rip, &regs, &memOps[0], &decodedLen)
	if n > decoderMaxMemOps {
		n = decoderMaxMemOps
	}
	if n == 0 {
		return
	}

	// extract_mem_addr already packs mem_op_infos with only real operands (num_bytes > 0);
	// no need to filter zero-length address-generation-only entries here.
	//
	// decoderRecordMemOp (Step 1 testing/diagnostic scaffolding) is commented out -- see
	// its definition above.
	// for i := uint32(0); i < n; i++ {
	// 	decoderRecordMemOp(regs.rip, &memOps[i])
	// }
	sampleAndWatch(c, gp, memOps[:n])
}

// sampleAndWatch captures the interrupted thread's own stack trace once, publishes each real
// operand (1 or 2) into its own activeWatchpoints slot, arms a watchpoint per operand on every
// other live M — concurrently, in one shared round, via a single armWatchpoints call — sleeps for
// the configurable window, then disarms everything it armed.
//
//go:nowritebarrierrec
func sampleAndWatch(c *sigctxt, gp *g, ops []decoderMemOpInfo) {
	// Mirrors sigprof's own guard immediately below in the same handler: this runs
	// concurrently with GC and must not allocate; incrementing mallocing++ will cause
	// any accidental allocation in the nested call to fail and fault.
	getg().m.mallocing++
	var u unwinder
	var stk [maxCPUProfStack]uintptr
	u.initAt(c.sigpc(), c.sigsp(), c.siglr(), gp, unwindSilentErrors|unwindTrap|unwindJumpStack)
	n := tracebackPCs(&u, 0, stk[:])
	getg().m.mallocing--

	var ops2 [decoderMaxMemOps]watchOp
	for i, op := range ops {
		isWrite := op.isWrite != 0
		publishActiveWatchpoint(i, op.addr, op.numBytes, isWrite, gp.goid, stk[:n])
		ops2[i] = watchOp{addr: op.addr, size: op.numBytes, isWrite: isWrite}
	}
	armWatchpoints(ops2[:len(ops)])
	usleep(uint32(debug.raceWatchWindowUs))
	disarmWatchpoints()
}

// decoderPrintMemOpTable dumps every recorded (instruction address -> memory
// operand) entry. Called once as the program exits so test programs can
// inspect what the SIGPROF path decoded over the run.
//
// Commented out along with decoderRecordMemOp above (its only source of data) -- Step 1
// testing/diagnostic scaffolding, not needed for Step 2. See decoder_stub.go and proc.go's
// runExitHooks for the matching commented-out stub and call site.
//
// func decoderPrintMemOpTable() {
// 	if !decoderReady.Load() {
// 		return
// 	}
// 	print("decoder: ", decoderMemOpCount.Load(), " memory operand(s) recorded via SIGPROF")
// 	var d uint32 = decoderMemOpDropped.Load()
// 	if d > 0 {
// 		print(" (", d, " dropped, table full)")
// 	}
// 	print("\n")
// 	for i := range decoderMemOpTable {
// 		var e *decoderMemOpEntry = &decoderMemOpTable[i]
// 		if !e.ready.Load() {
// 			continue
// 		}
// 		var instrAddr uint64 = e.key.Load()
// 		var op decoderMemOpInfo = e.op
// 		print("decoder: instr=", hex(instrAddr), " addr=", hex(op.addr),
// 			" bytes=", op.numBytes, " write=", op.isWrite != 0, "\n")
// 	}
// }
