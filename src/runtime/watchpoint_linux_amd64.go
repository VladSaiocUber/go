// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import "internal/runtime/atomic"

// perfEventAttr mirrors struct perf_event_attr from linux/perf_event.h, field-for-field, up to
// and including the sig_data field added in PERF_ATTR_SIZE_VER7 (128 bytes). Field order and
// widths must match the kernel struct exactly, since it is passed by pointer to the raw
// perfEventOpen syscall wrapper (sys_linux_amd64.s). config3 (added in a later ABI version) is
// included for documentation only and always left zero; we always declare size=perfAttrSizeVer7
// so the kernel only reads through sig_data.
type perfEventAttr struct {
	typ          uint32
	size         uint32
	config       uint64
	samplePeriod uint64 // union with sample_freq; we only ever use sample_period
	sampleType   uint64
	readFormat   uint64

	// Packed 64-bit bitfield: disabled:1, inherit:1, pinned:1, exclusive:1, exclude_user:1,
	// exclude_kernel:1, exclude_hv:1, exclude_idle:1, mmap:1, comm:1, freq:1,
	// inherit_stat:1, enable_on_exec:1, task:1, watermark:1, precise_ip:2, mmap_data:1,
	// sample_id_all:1, exclude_host:1, exclude_guest:1, exclude_callchain_kernel:1,
	// exclude_callchain_user:1, mmap2:1, comm_exec:1, use_clockid:1, context_switch:1,
	// write_backward:1, namespaces:1, ksymbol:1, bpf_event:1, aux_output:1, cgroup:1,
	// text_poke:1, build_id:1, inherit_thread:1, remove_on_exec:1, sigtrap:1,
	// __reserved_1:26. We set pinned, remove_on_exec and sigtrap (see the perfBit* constants
	// below); disabled is left clear (0) so the event is active immediately on creation.
	bits uint64

	wakeupEvents     uint32 // union with wakeup_watermark; unused, left zero
	bpType           uint32
	bpAddr           uint64 // union with kprobe_func/uprobe_path/config1
	bpLen            uint64 // union with kprobe_addr/probe_offset/config2
	branchSampleType uint64
	sampleRegsUser   uint64
	sampleStackUser  uint32
	clockid          int32
	sampleRegsIntr   uint64
	auxWatermark     uint32
	sampleMaxStack   uint16
	reserved2        uint16
	auxSampleSize    uint32
	reserved3        uint32
	sigData          uint64
	config3          uint64 // VER8+; always left zero, not covered by perfAttrSizeVer7
}

const (
	perfAttrSizeVer7 = 128 // PERF_ATTR_SIZE_VER7: size to declare in perfEventAttr.size

	// perfBitPinned, perfBitRemoveOnExec and perfBitSigtrap are the positions of the
	// pinned:1, remove_on_exec:1 and sigtrap:1 bits within perfEventAttr.bits, counting from
	// disabled:1 at bit 0. Verified by direct memory inspection of a real compiled struct
	// perf_event_attr (not just counting the header's field list by hand): bits 2, 36 and 37
	// respectively.
	//
	// The kernel rejects sigtrap=1 with EINVAL unless remove_on_exec=1 is also set —
	// confirmed empirically (not documented in the man page as of this writing): a
	// synchronous-signal-on-overflow event tied to a specific address doesn't make sense to
	// keep alive across an exec() that replaces the address space, so the kernel requires
	// the pairing. Both bits must always be set together.
	//
	// pinned demands the kernel guarantee this breakpoint stays resident on the actual
	// hardware debug register for as long as it's armed, failing perfEventOpen loudly up
	// front instead of silently time-multiplexing it off the PMU under register contention
	// (the default, pinned=0/"flexible", could otherwise let a real conflicting access go
	// undetected with no error anywhere). armWatchpoints already treats a failed open as
	// best-effort-skip, so no other code change is needed to handle that.
	perfBitPinned       = 1 << 2
	perfBitRemoveOnExec = 1 << 36
	perfBitSigtrap      = 1 << 37
)

//go:noescape
func perfEventOpen(attr *perfEventAttr, pid, cpu, groupFd int32, flags uint64) int32

// activeWatchpoints holds up to two concurrently-armed candidate races: slot i is the address
// range Thread A (the sampling thread) just accessed via the i-th real memory operand of the
// sampled instruction (most instructions have one; movs/cmps-style instructions can have two —
// see sampleAndWatch in decoder_linux_amd64.go), and Thread A's stack trace at that moment. Two
// fixed slots, not a full per-address table (see race_detector_plan.md Design Decisions).
// generation is bumped around every publish; not yet consumed by any reader (handleWatchpointTrap
// doesn't check it in this MVP) but present for future staleness detection.
//
// addr/size are the original, full memory operand — used for the human-readable race report
// (printRaceReport) — while armedAddr/armedLen are the specific hardware-supported sub-region
// armWatchpoints actually armed for this slot (pickWatchRegion's result). These can differ from
// a fresh pickWatchRegion(addr, size) call: when more than one aligned window fits, pickWatchRegion
// picks one at random, so recomputing it later (as decodeAccessorDirection used to) can silently
// pick a *different* window than the one really armed. armedAddr/armedLen are recorded once, at
// arm time, precisely so nothing needs to be recomputed.
var activeWatchpoints [2]struct {
	generation  atomic.Uint64
	addr        uint64
	size        uint32
	armedAddr   uint64
	armedLen    uint32
	isWrite     bool
	creatorGoid uint64
	creatorN    int32
	creatorPCs  [maxCPUProfStack]uintptr
}

// publishActiveWatchpoint records the just-decoded access, the sampling goroutine's id, and its
// stack (pcs) into activeWatchpoints[slot]. Called from sampleAndWatch before arming any
// watchpoints.
//
//go:nosplit
//go:nowritebarrierrec
func publishActiveWatchpoint(slot int, addr uint64, size uint32, isWrite bool, goid uint64, pcs []uintptr) {
	aw := &activeWatchpoints[slot]
	aw.generation.Add(1) // odd: publish in progress
	aw.addr = addr
	aw.size = size
	aw.isWrite = isWrite
	aw.creatorGoid = goid
	aw.creatorN = int32(copy(aw.creatorPCs[:], pcs))
	aw.generation.Add(1) // even: stable
}

// pickWatchRegion returns a hardware-supported (1/2/4/8-byte, aligned) sub-region fully
// contained within [addr, addr+size). x86 hardware breakpoints only support these four
// lengths, address-aligned to the length. We deliberately round DOWN, never up: the returned
// region is always a subset of the real access, so a watchpoint built from it can never trigger
// on a byte the program didn't actually touch (no false positives from the rounding itself), at
// the cost of possibly missing a conflicting access confined to the untracked remainder (a false
// negative). Always succeeds: size >= 1 (guaranteed by the numBytes > 0 check upstream) means
// the length-1 case always applies, since any address is trivially 1-aligned.
//
// Common case (size already 1, 2, 4 or 8 — true for the vast majority of sampled accesses,
// ordinary scalar mov/cmp instructions): if addr also happens to already be aligned to size,
// the whole access is directly watchable and we return immediately, skipping the general
// search below.
//
// Otherwise (size doesn't fit one of the four lengths, or addr isn't aligned to it), fall back
// to the general search: try the largest length first, and for the chosen length pick
// uniformly at random among every aligned window of that length fully contained in the
// access, rather than always the lowest one. This matters whenever more than one such window
// exists — most commonly once the chosen length (max 8) is smaller than size, which is the
// common case for AVX/vector loads and stores (16/32/64-byte operands): a fixed always-lowest
// choice would permanently blind the detector to a conflict confined to the rest of a wide
// access, sample after sample. Randomizing the window spreads coverage across the whole access
// over many SIGPROF samples instead — still a per-sample false negative (only one
// length-8-or-less slice of the access is ever watched at a time), but no longer the *same*
// slice every time. When only one window exists (the common aligned scalar case, and some
// misaligned ones too), that's detected directly and cheaprandn is skipped entirely. See
// "Known Limitations" in race_detector_plan.md.
//
//go:nosplit
func pickWatchRegion(addr uint64, size uint32) (waddr uint64, wlen uint32) {
	switch size {
	// well-aligned case
	case 1, 2, 4, 8:
		if addr&uint64(size-1) == 0 {
			return addr, size
		}
	}

	// not well-aligned case
	end := addr + uint64(size)
	for _, l := range [...]uint32{8, 4, 2, 1} {
		if l > size {
			continue
		}
		mask := uint64(l) - 1
		lo := (addr + mask) &^ mask // lowest l-aligned address >= addr
		if lo+uint64(l) > end {
			continue // no aligned l-byte window fits
		}
		hi := (end - uint64(l)) &^ mask // highest l-aligned address <= end-l
		if lo == hi {
			return lo, l
		}
		windows := (hi-lo)/uint64(l) + 1
		return lo + uint64(cheaprandn(uint32(windows)))*uint64(l), l
	}
	// Unreachable given size >= 1, but keep a safe fallback.
	return addr, 1
}

// watchOp is one operand's worth of arming input: the access sampleAndWatch decoded and wants
// watched on every other thread. ops[slot] always corresponds to activeWatchpoints[slot] and
// mp.watchpointFD[slot].
type watchOp struct {
	addr    uint64
	size    uint32
	isWrite bool
}

// armWatchpoints opens one PERF_TYPE_BREAKPOINT event per op directly against every other live
// M's tid, watching the region pickWatchRegion selects for each op's [addr, addr+size). An op's
// isWrite selects HW_BREAKPOINT_RW (the original access was a Write, so any Read or Write by
// another thread is a conflict) vs HW_BREAKPOINT_W (the original access was a Read, so only a
// Write conflicts).
//
// Note: for the RW case, we cannot determine whether the *accessor's* conflicting access was
// itself a Read or a Write without extra work — a single HW_BREAKPOINT_R-only watch isn't a
// choice available here: confirmed empirically that x86 hardware debug registers have no
// read-only mode at all (DR7's RW field only encodes execute/write-only/read-write), so
// HW_BREAKPOINT_R alone reliably fails with EINVAL. A prior version of this code tried arming two
// separate watches (write-only + read-only) to determine direction deterministically; reverted
// because the read-only half silently never armed, quietly losing Read-vs-Write conflict
// detection for every RW-armed watch. See handleWatchpointTrap/printRaceReport for the current
// (approximate) direction handling and race_detector_plan.md for the open plan to properly fix
// this (LBR-based instruction recovery is under investigation as of this writing).
//
// len(ops) is 1 for an ordinary single-operand instruction, or 2 for an instruction with two real
// memory operands (movs/cmps) — both are armed concurrently in this one call rather than via two
// separate rounds, so a conflicting access to either address during the same window is caught
// (see decoder_linux_amd64.go's sampleAndWatch). Each perf_event_open call targets the other
// thread directly (pid = its tid) — no cooperation or signal to that thread is needed; see
// race_detector_plan.md Section 2.B for why this requires no elevated privilege and why any
// thread can close an fd opened on another thread's behalf. Each watchpoint's sigData is set to
// its slot index (0 or 1) so handleWatchpointTrap can later tell, via si_perf_data, which of the
// (up to) two watched addresses actually fired.
//
// Deliberately not //go:nosplit: this only runs from within sampleAndWatch, which is itself not
// nosplit — see the comment there for why.
//
//go:nowritebarrierrec
func armWatchpoints(ops []watchOp) {
	var attrs [2]perfEventAttr
	for i := range ops {
		waddr, wlen := pickWatchRegion(ops[i].addr, ops[i].size)
		activeWatchpoints[i].armedAddr = waddr
		activeWatchpoints[i].armedLen = wlen

		bpType := uint32(_HW_BREAKPOINT_W)
		if ops[i].isWrite {
			bpType = _HW_BREAKPOINT_RW
		}

		attrs[i].typ = _PERF_TYPE_BREAKPOINT
		attrs[i].size = perfAttrSizeVer7
		attrs[i].samplePeriod = 1
		attrs[i].bits = perfBitSigtrap | perfBitRemoveOnExec | perfBitPinned
		attrs[i].bpType = bpType
		attrs[i].bpAddr = waddr
		attrs[i].bpLen = uint64(wlen)
		attrs[i].sigData = uint64(i)
	}

	self := getg().m
	for mp := allm; mp != nil; mp = mp.alllink {
		if mp == self {
			continue
		}
		pid := int32(atomic.Load64(&mp.procid))
		if pid == 0 {
			continue // thread hasn't started yet
		}
		for i := range ops {
			fd := perfEventOpen(&attrs[i], pid, -1, -1, 0)
			if fd < 0 {
				continue // best-effort: e.g. thread exited (ESRCH) or perf unavailable (EACCES)
			}
			// Never plain-Store: another, concurrently-sampling thread may already have a
			// live watchpoint fd installed on this same target M's slot. Swap-and-close-if-
			// valid so any superseded watchpoint is closed immediately instead of leaked
			// (see race_detector_plan.md Design Decision 3).
			if old := mp.watchpointFD[i].Swap(fd); old >= 0 {
				closefd(old)
			}
		}
	}
}

// disarmWatchpoints closes every watchpoint fd this thread's own armWatchpoints call installed,
// in both slots (and, incidentally, any fd installed by some other concurrently-sampling thread's
// arm round that landed on the same target M/slot in the interim — that's fine, it's still a
// supersede-and-close, never a leak or a double-close, since watchpointFD is only ever mutated
// via swap).
//
//go:nowritebarrierrec
func disarmWatchpoints() {
	self := getg().m
	for mp := allm; mp != nil; mp = mp.alllink {
		if mp == self {
			continue
		}
		for i := range mp.watchpointFD {
			if fd := mp.watchpointFD[i].Swap(-1); fd >= 0 {
				closefd(fd)
			}
		}
	}
}

// handleWatchpointTrap is called from sighandler on every SIGTRAP. It checks si_code itself
// (rather than requiring the cross-platform caller in signal_unix.go to reference any
// linux/amd64-only constant) and returns false immediately unless si_code == _TRAP_PERF: this
// thread's own hardware watchpoint (armed on it by some other, sampling thread) just triggered.
// It then reads si_perf_data (via c.sigperfdata()) to learn which slot (0 or 1) fired — each
// watchpoint was armed with sigData set to its own slot index, precisely so this can be
// determined. Also returns false if that slot has no live watchpoint fd recorded (the trap is
// spurious, or Thread A's disarm pass already closed it out from under this trap) so the caller
// can fall through to normal SIGTRAP handling instead.
//
// Deliberately not //go:nosplit: same reasoning as sampleAndWatch/armWatchpoints — the
// unwinder.initAt/tracebackPCs call chain is too deep for the nosplit linker budget, and
// sighandler (our only caller) isn't nosplit either.
//
//go:nowritebarrierrec
func handleWatchpointTrap(c *sigctxt, gp *g) bool {
	if c.sigcode() != _TRAP_PERF {
		return false
	}
	slot := int(c.sigperfdata())
	if slot != 0 && slot != 1 {
		return false // defensive; we only ever arm sigData as 0 or 1
	}
	mp := getg().m
	fd := mp.watchpointFD[slot].Swap(-1)
	if fd < 0 {
		return false
	}
	closefd(fd)

	// Guard only the capture itself (matching sigprof's scope), not the report/exit below:
	// we're about to hard-exit the process either way, and printRaceReport's symbolication
	// path isn't proven allocation-free, so throwing instead of printing our race report
	// here would defeat the point of catching the race at all.
	getg().m.mallocing++
	var u unwinder
	var stk [maxCPUProfStack]uintptr
	u.initAt(c.sigpc(), c.sigsp(), c.siglr(), gp, unwindSilentErrors|unwindTrap|unwindJumpStack)
	n := tracebackPCs(&u, 0, stk[:])
	getg().m.mallocing--

	// If the creator's own access was a Read, the watch armed was HW_BREAKPOINT_W-only, so the
	// only thing that could have tripped it is a Write — deterministically correct, no
	// decoding needed. Only bother with the backward-decode below for the genuinely ambiguous
	// case (creator's access was a Write, so an HW_BREAKPOINT_RW watch was armed and either
	// direction could have tripped it).
	accessorIsWrite := true
	if activeWatchpoints[slot].isWrite {
		if decodedIsWrite, ok := decodeAccessorDirection(c, slot); ok {
			accessorIsWrite = decodedIsWrite
		}
		// else: fall through with the accessorIsWrite=true default — a documented, rare
		// fallback (see decodeAccessorDirection) for when the backward scan finds no
		// candidate confidently matching both the instruction-length and watched-address
		// checks.
	}

	printRaceReport(slot, accessorIsWrite, gp.goid, stk[:n])
	exit(2)
	return true
}

// decoderMaxBackwardBytes matches MAX_BYTES_PER_INSTR in decoder.c: the longest an x86
// instruction can be, and so the furthest before %rip the instruction that trapped a watchpoint
// could possibly have started.
const decoderMaxBackwardBytes = 15

// decodeAccessorDirection recovers whether the access that tripped activeWatchpoints[slot]'s
// hardware watchpoint was itself a Read or a Write, for the case where that's genuinely
// ambiguous from the watch type alone (the creator's own access was a Write, so an
// HW_BREAKPOINT_RW watch was armed and either direction could have tripped it — see
// handleWatchpointTrap).
//
// x86 *data* breakpoints trap after the instruction retires, so %rip at SIGTRAP time already
// points past the triggering instruction — decoding forward from c.rip() decodes the wrong
// instruction (confirmed empirically: an earlier version of this code did exactly that and
// produced a wrong Read/Write label). Instead, this decodes backward: for each candidate start
// offset 1..15 bytes before %rip, it asks the decoder whether those bytes form a valid
// instruction whose length lands exactly on %rip.
//
// A length match alone is not reliable enough to trust by itself: confirmed empirically (by
// decoding every byte offset, not just the real instruction boundaries, of a short real
// instruction sequence) that XED has no way to tell it's being asked to decode from the middle
// of another instruction, and a surprisingly common case — an offset landing exactly one byte
// late, right after a ubiquitous single-byte REX prefix — often decodes the remaining bytes into
// a *different but still valid* unprefixed instruction that's exactly one byte shorter and so
// ends at the identical %rip. So this also requires the candidate's own decoded memory operand
// to actually overlap the address this watchpoint was armed for (using the real register
// snapshot from the trap) — a spurious mid-instruction decode is exceedingly unlikely to also
// compute the exact watched address from entirely different bytes interpreted as different
// base/index/displacement fields.
//
// ok is false if no candidate satisfies both checks (rare — e.g. the true instruction starts
// within decoderMaxBackwardBytes of the start of its page, or some other decode edge case);
// the caller falls back to its own default in that case.
//
//go:nowritebarrierrec
func decodeAccessorDirection(c *sigctxt, slot int) (isWrite, ok bool) {
	rip := c.rip()
	watchAddr, watchLen := activeWatchpoints[slot].armedAddr, activeWatchpoints[slot].armedLen

	// Never read before the start of %rip's page: mirrors decoder.c's bytes_remain_in_page
	// guard for forward decoding, just in the other direction. %rip is a currently-executing
	// code address, so anything within the same page is guaranteed mapped and readable.
	maxBack := decoderMaxBackwardBytes
	if avail := rip & 0xFFF; avail < uint64(maxBack) {
		maxBack = int(avail)
	}

	var regs decoderRegs = decoderRegs{
		rax: c.rax(), rcx: c.rcx(), rdx: c.rdx(), rbx: c.rbx(),
		rsp: c.rsp(), rbp: c.rbp(), rsi: c.rsi(), rdi: c.rdi(),
		r8: c.r8(), r9: c.r9(), r10: c.r10(), r11: c.r11(),
		r12: c.r12(), r13: c.r13(), r14: c.r14(), r15: c.r15(),
		rip: rip,
	}

	for k := 1; k <= maxBack; k++ {
		candAddr := rip - uint64(k)
		var memOps [decoderMaxMemOps]decoderMemOpInfo
		var length uint32
		n := decoderExtractMemAddrCall(candAddr, &regs, &memOps[0], &length)
		if length != uint32(k) {
			continue // decode failed outright (length 0), or doesn't end exactly at rip
		}
		if n > decoderMaxMemOps {
			n = decoderMaxMemOps
		}
		// extract_mem_addr already packs mem_op_infos with only real operands
		// (num_bytes > 0); no need to filter zero-length entries here.
		for i := uint32(0); i < n; i++ {
			if rangesOverlap(memOps[i].addr, memOps[i].numBytes, watchAddr, watchLen) {
				return memOps[i].isWrite != 0, true
			}
		}
	}
	return false, false
}

// rangesOverlap reports whether [addr1, addr1+len1) and [addr2, addr2+len2) share any bytes.
//
//go:nosplit
func rangesOverlap(addr1 uint64, len1 uint32, addr2 uint64, len2 uint32) bool {
	return addr1 < addr2+uint64(len2) && addr2 < addr1+uint64(len1)
}

// printRaceReport prints a data race report in the same text format the standard race detector
// (TSan) uses, so external tooling that already parses that format (e.g.
// go-racelite-experiment's race.go) can be reused as-is: a "Write at ADDR by goroutine N
// [running]:" (or "Read at") header followed by the triggering access's stack, a blank line,
// then "Previous write at ADDR by goroutine N [running]:" (or "Previous read at") followed by
// activeWatchpoints[slot]'s saved creator stack (the sampling thread that armed this
// watchpoint). Reuses the same PC-array symbolication the runtime already uses for ancestor
// goroutine tracebacks (printAncestorTracebackFuncInfo in traceback.go) for each frame, rather
// than reinventing symbolication here.
func printRaceReport(slot int, accessorIsWrite bool, accessorGoid uint64, accessorPCs []uintptr) {
	aw := &activeWatchpoints[slot]

	print("==================\n")
	print("WARNING: DATA RACE\n")

	accessorKind := "Read"
	if accessorIsWrite {
		accessorKind = "Write"
	}
	print(accessorKind, " at ", hex(aw.addr), " by goroutine ", accessorGoid, " [running]:\n")
	printPCs(accessorPCs)

	print("\n")

	creatorKind := "write"
	if !aw.isWrite {
		creatorKind = "read"
	}
	print("Previous ", creatorKind, " at ", hex(aw.addr), " by goroutine ", aw.creatorGoid, " [running]:\n")
	printPCs(aw.creatorPCs[:aw.creatorN])

	print("==================\n")
}

// printPCs prints a symbolicated stack trace from a raw PC array captured earlier (via
// unwinder.initAt + tracebackPCs), matching the technique printAncestorTraceback uses to print a
// long-since-captured ancestor goroutine's stack from stored PCs.
func printPCs(pcs []uintptr) {
	for _, pc := range pcs {
		f := findfunc(pc)
		if !f.valid() {
			continue
		}
		printAncestorTracebackFuncInfo(f, pc)
	}
}
