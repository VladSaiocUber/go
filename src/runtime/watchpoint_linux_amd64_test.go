// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	. "runtime"
	"testing"
)

func TestPickWatchRegion(t *testing.T) {
	cases := []struct {
		addr, size uint64
		// wantWaddrs lists every waddr PickWatchRegion is allowed to return for this
		// case. Most cases have exactly one aligned window of the winning length and so
		// are still fully deterministic; the size=16 case has two (the window is chosen
		// at random — see the "size=16" case below and TestPickWatchRegionRandomizes).
		wantWaddrs []uint64
		wantWlen   uint32
	}{
		// 8-byte-aligned, 8-byte access: exact fit, taken via the size-already-supported
		// fast path.
		{addr: 0x1000, size: 8, wantWaddrs: []uint64{0x1000}, wantWlen: 8},
		// 8-byte-aligned, larger access: length still caps at 8 (the largest supported),
		// but which of the two fully-contained 8-byte windows is picked is randomized.
		{addr: 0x2000, size: 16, wantWaddrs: []uint64{0x2000, 0x2008}, wantWlen: 8},
		// Aligned but too small for 8/4: falls to the largest length that fits, 2. Only
		// one aligned window of length 2 fits, so still deterministic.
		{addr: 0x1000, size: 3, wantWaddrs: []uint64{0x1000}, wantWlen: 2},
		// Misaligned start, 4-byte access: no aligned 8 or 4-byte region fits inside
		// [0x1003, 0x1007), but an aligned 2-byte region does: [0x1004, 0x1006).
		{addr: 0x1003, size: 4, wantWaddrs: []uint64{0x1004}, wantWlen: 2},
		// Single-byte access: only length 1 ever fits, trivially aligned to itself.
		{addr: 0x1001, size: 1, wantWaddrs: []uint64{0x1001}, wantWlen: 1},
		// Odd address, 3-byte access [0x1001, 0x1004): no aligned 4-byte region fits, but
		// an aligned 2-byte region does, at the next-higher-aligned address: [0x1002, 0x1004).
		{addr: 0x1001, size: 3, wantWaddrs: []uint64{0x1002}, wantWlen: 2},
		// 4-byte-aligned but not 8-byte-aligned, 8-byte access: two candidate 4-byte
		// windows exist ([0x1004, 0x1008) and [0x1008, 0x100c)), and which one is picked
		// is randomized just like the size=16 case above.
		{addr: 0x1004, size: 8, wantWaddrs: []uint64{0x1004, 0x1008}, wantWlen: 4},
	}

	for _, c := range cases {
		waddr, wlen := PickWatchRegion(c.addr, uint32(c.size))
		if !containsU64(c.wantWaddrs, waddr) || wlen != c.wantWlen {
			t.Errorf("PickWatchRegion(%#x, %d) = (%#x, %d), want waddr in %#x with wlen %d",
				c.addr, c.size, waddr, wlen, c.wantWaddrs, c.wantWlen)
		}
		// The chosen region must always be fully contained within [addr, addr+size) —
		// the core no-false-positive-from-rounding invariant.
		if waddr < c.addr || waddr+uint64(wlen) > c.addr+c.size {
			t.Errorf("PickWatchRegion(%#x, %d) = (%#x, %d) is not contained within the original range",
				c.addr, c.size, waddr, wlen)
		}
		// The chosen length must be one of the four hardware-supported lengths and the
		// chosen address must actually be aligned to it.
		switch wlen {
		case 1, 2, 4, 8:
		default:
			t.Errorf("PickWatchRegion(%#x, %d) returned unsupported length %d", c.addr, c.size, wlen)
		}
		if waddr%uint64(wlen) != 0 {
			t.Errorf("PickWatchRegion(%#x, %d) = (%#x, %d) is not aligned to its own length",
				c.addr, c.size, waddr, wlen)
		}
	}
}

func containsU64(haystack []uint64, v uint64) bool {
	for _, h := range haystack {
		if h == v {
			return true
		}
	}
	return false
}

// TestPickWatchRegionRandomizes checks that, for a wide (>8-byte) access with more than one
// candidate 8-byte window, repeated calls actually explore more than just the lowest window —
// the whole point of randomizing the window (see pickWatchRegion's doc comment). A fixed
// always-lowest choice would permanently miss any conflict confined to the rest of a wide
// AVX/vector access; this only checks that both windows get visited at all, not any particular
// distribution.
func TestPickWatchRegionRandomizes(t *testing.T) {
	const addr, size = 0x4000, 32 // four candidate 8-byte windows: 0x4000, 0x4008, 0x4010, 0x4018
	seen := map[uint64]bool{}
	for i := 0; i < 1000; i++ {
		waddr, wlen := PickWatchRegion(addr, size)
		if wlen != 8 {
			t.Fatalf("PickWatchRegion(%#x, %d) returned wlen %d, want 8", addr, size, wlen)
		}
		seen[waddr] = true
	}
	want := []uint64{0x4000, 0x4008, 0x4010, 0x4018}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("PickWatchRegion(%#x, %d) never returned window %#x across 1000 calls", addr, size, w)
		}
	}
}
