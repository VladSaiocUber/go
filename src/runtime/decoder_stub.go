// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !(linux && amd64)

// The XED-based instruction decoder (see decoder_linux_amd64.go) is only
// built for linux/amd64, since decoder_linux_amd64.syso is compiled for
// that target. These are no-op stand-ins everywhere else.

package runtime

func decoderInit() {}

//go:nosplit
//go:nowritebarrierrec
func decoderHandleSigprof(c *sigctxt) {}

func decoderPrintMemOpTable() {}
