// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build racelite

package runtime

import (
	"internal/goarch"
	"internal/runtime/sys"
)

const (
	// raceliteVRShift is log2(raceliteVRNum).
	raceliteVRShift uint8 = 4
	// raceliteVRNum is the number of virtual registers we have.
	// Keep as power of 2 for efficient modulo operation.
	raceliteVRNum = 1 << raceliteVRShift

	// raceliteRecordShift is log2(raceliteRecordNum).
	raceliteRecordShift uint8 = 13
	// raceliteRecordNum is the number of data race records we have.
	raceliteRecordNum = 1 << raceliteRecordShift

	// racelitePCDepth is the number of program counters to store
	// in data race record stacks.
	racelitePCDepth = 16

	// These values denote the type of the accesses involved
	// in a race as follows (assume BE):
	//
	//	 .----> Second operation (latest)
	//	 | .--> First operation (previous)
	//	 ___
	//	|0|0: write-write (default)
	//	|0|1: read-write
	//	|1|0: write-read
	//
	// Every other bit-value is invalid.
	//
	// They are used to determine the access type pair.
	raceliteOp1Read, raceliteOp2Read uint8 = 0b01, 0b10

	// raceliteTempShift is log2(raceliteTempSize).
	raceliteTempShift uint8 = 16
	// raceliteTempSize is the size of the array that
	// monitors the temperature of PCs.
	raceliteTempSize = 1 << raceliteTempShift
)

var (
	// raceliteSamplingRand allows us to randomize which addresses we check for racelite,
	// but to do so in a way we get a consistent answer per address across concurrent readers
	// and writers.
	//
	// TODO(thepudds): for now, for convenience we only check this in runtime, but we
	// could have the compiler emit the check -- probably important to do or at least
	// try if were were to pursue this general approach.
	raceliteSamplingRand uint32 = 0

	// raceliteReg is the global array of virtual registers.
	raceliteReg *[raceliteVRNum]raceliteVirtualRegister

	// raceliteTemp is the array that monitors PC temperatures.
	// The higher the temperature, the less likely for the PC
	// to execute the instrumentation.
	raceliteTemp *[raceliteTempSize]uint32

	// raceliteRecords is the array that records which data race
	// have been reported to prevent duplicates.
	raceliteRecords *[raceliteRecordNum]bool

	// raceliteSamplingShift is log2(raceliteSamplingMask+1)
	raceliteSamplingShift uint32
	// raceliteSamplingMask is used when determining whether to sample an address.
	raceliteSamplingMask uint32
)

// Initialize Racelite tooling
func raceliteinit() {
	// Initialize the random address sampler.
	raceliteSamplingRand = cheaprand()

	// Sample one address (8-byte aligned) in every 4096.
	raceliteSamplingShift = 11
	raceliteSamplingMask = (1 << raceliteSamplingShift) - 1

	// Initialize virtual registers.
	raceliteReg = new([raceliteVRNum]raceliteVirtualRegister)
	for i := 0; i < raceliteVRNum; i++ {
		// Assign an identifier to the virtual register.
		// This is used for debugging and experimentation.
		raceliteReg[i].identifier = uint32(i)
	}

	// Initialize data race records
	raceliteRecords = new([raceliteRecordNum]bool)

	// Initialize instrumented PC temperatures
	raceliteTemp = new([raceliteTempSize]uint32)
}

// racelitetick refreshes the sampler and reduces
// the temperature of all the instrumented PCs, depending
// on the delay of the tick.
func racelitetick(delay uint32) {
	raceliteSamplingRand = cheaprand()
	// Appropriately reduce temperature based on the delay.
	decrement := uint32(sys.Len64(uint64(delay)))

	for i := 0; i < raceliteTempSize; i++ {
		temp := raceliteTemp[i]
		raceliteTemp[i] = temp - min(temp, decrement)
	}
}

// racelitecount reports how many data races were found during execution.
//
// It is called by main and os_beforeExit (proc.go).
func racelitecount() {
	var count int32
	for _, filled := range raceliteRecords {
		if filled {
			count++
		}
	}
	if count > 0 {
		print("Found ", count, " data race(s)\n")
	}
}

// racelitepause injects a small delay to a load
// or store operation, allowing Racelite to see
// whether another thread accessed the same address.
// The pause probability is weighted by PC temperature.
//
//go:nosplit
func racelitepause(temp uint32) {
	// We stochastically skip the micropause if the given PC is too hot.
	if !racelitehotskip(temp) {
		usleep(5)
	}
}

// racelitemixpcs combines pcs in an array up to a given length
// into a single value, which can then be hashed using racelitehash.
//
//go:nosplit
func racelitemixpcs(pcs *[racelitePCDepth]uintptr, n int) uintptr {
	var combinedPC uintptr = 0
	for i := 0; i < n; i++ {
		combinedPC = 31*combinedPC + pcs[i]
	}
	return combinedPC
}

// racelitehash computes the Fibonacci hash of the given value,
// then compressing it into a range of [0, 2^shift).
//
//go:nosplit
func racelitehash(v uintptr, shift uint8) uintptr {
	const k = 0x9e3779b97f4a7c15 // golden ratio
	return (v * k) >> (goarch.PtrSize*8 - shift)
}

// raceliteraceheat drastically increases the temperature
// of a PC where a data race has been detected.
//
//go:nosplit
func raceliteraceheat(pc uintptr) {
	slot := racelitehash(pc, raceliteTempShift)
	temp := raceliteTemp[slot]
	raceliteTemp[slot] = min(1024, (temp+1)<<3)
}

// racelitetemp gets the temperature for the given PC, incrementing it.
// Returns the temperature after increment.
//
// callerPC should be the PC of the instrumented memory access site,
// obtained via sys.GetCallerPC() in raceliteread or racelitewrite.
//
//go:nosplit
func racelitetemp(pc uintptr) uint32 {
	hash := racelitehash(pc, raceliteTempShift)
	raceliteTemp[hash] = min(1024, raceliteTemp[hash]+1)
	temp := raceliteTemp[hash]
	return temp
}

// racelitehotskip stochastically uses temperature to make decisions.
// Higher temperature → higher probability of returning true.
// Used for both skipping instrumentation and micropause decisions.
func racelitehotskip(temp uint32) bool {
	t := uint32(sys.Len64(uint64(temp) >> 3))
	return t > 0 && cheaprandn(t) != 0
}

// racelitesampled checks if we should sample the given address for data race detection.
//
//go:nosplit
func racelitesampled(addr uintptr) bool {
	// Check that we are sampling this address, stripped of
	// a (3+raceliteVRShift)-bit suffix for 8-byte alignment
	// and because we have enough virtual registers.
	if (uint32(addr>>(3+raceliteVRShift))^raceliteSamplingRand)&raceliteSamplingMask != 0 {
		return false
	}

	// Check that this address is not on our stack.
	gp := getg()
	if gp.stack.lo <= addr && addr < gp.stack.hi {
		// Ignore stack addresses
		return false
	}

	// Globals path: data/BSS segments of the main binary and any
	// dynamically-loaded plugins. The four segments are not guaranteed
	// to be contiguous under external linking (see mfinal.go), so we
	// check each range explicitly per module.
	for datap := &firstmoduledata; datap != nil; datap = datap.next {
		if datap.noptrdata <= addr && addr < datap.enoptrdata ||
			datap.data <= addr && addr < datap.edata ||
			datap.bss <= addr && addr < datap.ebss ||
			datap.noptrbss <= addr && addr < datap.enoptrbss {
			return true
		}
	}

	// Heap path: most monitored addresses live here.
	base, span, _ := findObject(uintptr(addr), 0, 0)
	// Only return true if it is a valid object.
	return base != 0 && span != nil
}

// raceliteVirtualRegister is a virtual register that can be used to
// dynamically monitor an address for data races.
type raceliteVirtualRegister struct {
	// Mutual exclusion ensures that the virtual register maintains a consistent state.
	rwmutex

	// addr is the address currently being monitored in the virtual register
	addr uintptr

	// Program counters of racy stacks.
	//
	// pcs1 denotes the previous operation
	// pcs2 denotes the latest operation
	pcs1, pcs2 [racelitePCDepth]uintptr
	// Stack depth of racy goroutines (cannot exceed racelitePCDepth).
	//
	// n1 denotes the stack depth of the previous operation
	// n2 denotes the stack depth of the latest operation
	n1, n2 int
	// The racy goroutine IDs. goid1 denotes the goroutine ID of the previous operation
	// goid2 denotes the goroutine ID of the latest operation
	goid1, goid2 uint64

	// Diagnostics used in experiments.
	//
	// TODO(vsaioc): Add more for experimentation purposes and remove
	// for the polished release version.

	identifier uint32 // the identifier of the virtual register
}

// racelitegetvr returns the virtual register for the given address.
func racelitegetvr(addr uintptr) *raceliteVirtualRegister {
	// Compile-time optimized to bitwise AND.
	return &raceliteReg[(addr>>3)%raceliteVRNum]
}

// reportPC is short-hand for printing a stack trace to the console.
func (_ *raceliteVirtualRegister) reportPC(pcs [racelitePCDepth]uintptr, n int) {
	for _, pc := range pcs[:n] {
		if f := findfunc(pc); f.valid() {
			if pc > f.entry() {
				pc--
			}
			printAncestorTracebackFuncInfo(f, pc)
		}
	}
}

// report prints a data race report to the console.
// The reports match the format of the data race warnings
// issued by TSan (omitting ancestry information).
//
// Example:
//
//	==================
//	WARNING: DATA RACE
//	Write at 0x1234567890 by goroutine 123
//	[stack trace of the writer]
//
//	Previous write at 0x1234567890 by goroutine 456
//	[stack trace of the previous writer]
//	==================
//
// ops represents the type of racy operations.
// The trailing 2 bits (assume BE) carry the following meanings:
//
//	 ... b₂ | b₁ | b₀
//					  |    '> Type of first racy operation.
//						'> Type of second racy operation.
//
// where 0 denotes a write, and 1 denotes a read.
//
// For any 6-bit x, then:
//
//	x00: write-write (default)
//	x01: read-write
//	x10: write-read
//
// Every other value is invalid.
//
//go:nosplit
func (r *raceliteVirtualRegister) report(ops uint8) {
	// Perform all of this on the system stack to avoid copystack
	// during racelite instrumentation.
	systemstack(func() {
		pc1 := racelitemixpcs(&r.pcs1, r.n1)
		pc2 := racelitemixpcs(&r.pcs2, r.n2)
		slot := racelitehash(((pc1 + pc2) ^ (pc1 * pc2)), raceliteRecordShift)

		if raceliteRecords[slot] {
			// We already recorded this data race previously.
			return
		}

		// Record the data race.
		raceliteRecords[slot] = true

		pcs1, n1, goid1 := r.pcs1, r.n1, r.goid1
		pcs2, n2, goid2 := r.pcs2, r.n2, r.goid2

		// We start by assuming a write-write race occured.
		var op1, op2 string = "write", "Write"
		switch {
		case ops&raceliteOp1Read != 0:
			// If a read-write race, occurred, then the temporal order of
			// goroutine 1 (the write) and goroutine 2 (the reader) is reversed
			// The writer occurred second, so is printed first, followed
			// by the reader.
			//
			// Swap the variables around.
			pcs1, n1, goid1 = r.pcs2, r.n2, r.goid2
			pcs2, n2, goid2 = r.pcs1, r.n1, r.goid1
			op1 = "read"
		case ops&raceliteOp2Read != 0:
			// Otherwise, if we are dealing with a write-read race,
			// list op2 as a Read.
			op2 = "Read"
		}

		// Use printlock to avoid jumbling the output.
		printlock()
		// Print the latest operation first (like TSan).
		print("==================\n",
			"WARNING: DATA RACE\n",
			op2, " at ", hex(r.addr), " by goroutine ", goid2, "\n")
		r.reportPC(pcs2, n2)
		print("\n",
			"Previous ", op1, " at ", hex(r.addr), " by goroutine ", goid1, "\n")
		r.reportPC(pcs1, n1)
		print("==================\n")
		printunlock()
	})
}

// claim sets the writer goroutine as the owner of the virtual register.
//
//go:nosplit
func (r *raceliteVirtualRegister) claim(addr uintptr) bool {
	r.lock()
	switch r.addr {
	case 0:
		// The virtual register is not occupied.
		// The writer can claim it.
		r.addr = addr

		r.goid1 = getg().goid        // Get goroutine ID.
		r.n1 = callers(2, r.pcs1[:]) // Copy its PC stack

		r.unlock()
		return true

	case addr:
		// The virtual register is already occupied by the same address.
		// This only happens if another writer intercepted the write.
		// We are, therefore, dealing with a write-write race.

		r.n2 = callers(2, r.pcs2[:racelitePCDepth]) // Get the PCs and stack depth of the current goroutine.
		r.goid2 = getg().goid                       // Get ID of the current goroutine

		// Heat up the previous writer PC.
		raceliteraceheat(r.pcs1[0])

		// Report the data race
		r.report(0)

		// We can now release the lock.
		r.unlock()
		return false

	default:
		// The virtual register is already occupied by another address.
		r.unlock()
		return false
	}
}

// monitor allows a reader goroutine to check whether the virtual
// register is occupied by a writer with the given address.
//
//go:nosplit
func (r *raceliteVirtualRegister) monitor(addr uintptr, ops uint8) bool {
	r.lock()
	// Check the status of the virtual register.
	if r.addr != addr {
		// The virtual register is occupied by another address.
		// This is not a data race.
		r.unlock()
		return false
	}

	// Place the reader in the second position regardless
	// of whether a read-write or write-read race occurred.
	//
	// We arrange the goroutines and disambiguate the type
	// of race while reporting.
	r.n2 = callers(2, r.pcs2[:])
	r.goid2 = getg().goid // Get goroutine ID of reader goroutine.

	// Heat up the reader PC where the data race occurred.
	raceliteraceheat(r.pcs2[0])

	r.report(ops)

	// Release the virtual register lock.
	r.unlock()

	return true
}

// release detaches the virtual register from the writer goroutine.
//
//go:nosplit
func (r *raceliteVirtualRegister) release() {
	r.lock()
	// We only need to clear the address. Other properties are updated
	// on the next claim.
	r.addr = 0
	r.unlock()
}

// racelitewrite instruments a store operation with data race detection,
// according to the following logic:
//
//	Let A be the stored address and V the virtual register
//
//	if V is claimed for A:
//		Report write-write race and return
//	claim V for A
//	pause
//	release V
//
//go:nosplit
func racelitewrite(addr uintptr) {
	if !racelitesampled(addr) {
		// We are not sampling this address.
		return
	}

	temp := racelitetemp(sys.GetCallerPC())

	r := racelitegetvr(addr)
	// Try to claim the virtual register.
	if !r.claim(addr) {
		// We did not claim the virtual register.
		// It was either claimed by another writer, or
		// we had a write-write race.
		return
	}

	racelitepause(temp)

	// Release the virtual register.
	r.release()
}

// raceliteread instruments a load operation with data race detection,
// according to the following logic:
//
//	Let A be the loaded address and V the virtual register
//
//	if V is claimed for A:
//		Report write-read race and return
//	pause
//	if V is claimed for A:
//		Report read-write race and return
//
//go:nosplit
func raceliteread(addr uintptr) {
	if !racelitesampled(addr) {
		// We are not sampling this address.
		return
	}

	temp := racelitetemp(sys.GetCallerPC())

	r := racelitegetvr(addr)
	// Check for a write-read race.
	if r.monitor(addr, raceliteOp2Read) {
		return
	}

	racelitepause(temp)

	// Check for a read-write race.
	r.monitor(addr, raceliteOp1Read)
}
