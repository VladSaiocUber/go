// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !(linux && amd64)

// The XED-based instruction decoder (see decoder_linux_amd64.go) is only
// built for linux/amd64, since decoder_linux_amd64.syso is compiled for
// that target. This is a no-op stand-in everywhere else: decoderInit is
// called from proc.go, which builds on every platform including non-unix
// ones, so it needs the broad tag above. raceSampleSigprof's stub lives
// separately, in decoder_stub_unix.go, since its signature depends on the
// unix-only sigctxt type (its only caller, sighandler in signal_unix.go, is
// itself //go:build unix).

package runtime

func decoderInit() {}

// decoderPrintMemOpTable's stub is commented out along with the real definition in
// decoder_linux_amd64.go and its call site in proc.go's runExitHooks -- see there.
//
// func decoderPrintMemOpTable() {}
