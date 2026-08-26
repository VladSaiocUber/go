// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix && !(linux && amd64)

// The hardware-watchpoint race detector (see watchpoint_linux_amd64.go) is only built for
// linux/amd64, since it depends on perf_event_open and the x86 hardware breakpoint ABI. This is
// a no-op stand-in for every other unix platform, called unconditionally from signal_unix.go's
// SIGTRAP branch. handleWatchpointTrap's only caller (sighandler) is itself //go:build unix, so
// non-unix platforms (windows, plan9, js) need no stub — and correspondingly can't provide one,
// since the sigctxt type used in the signature below is unix-only.

package runtime

//go:nosplit
//go:nowritebarrierrec
func handleWatchpointTrap(c *sigctxt, gp *g) bool { return false }
