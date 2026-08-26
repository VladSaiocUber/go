// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix && !(linux && amd64)

// raceSampleSigprof's no-op stand-in for every unix platform other than linux/amd64. Split out
// from decoder_stub.go because this signature depends on the unix-only sigctxt type: its only
// caller, sighandler in signal_unix.go, is itself //go:build unix, so non-unix platforms
// (windows, plan9, js) need no stub here at all — and correspondingly can't provide one.

package runtime

//go:nosplit
//go:nowritebarrierrec
func raceSampleSigprof(c *sigctxt, gp *g) {}
