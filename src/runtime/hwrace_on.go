// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build hwrace

// Build with -tags hwrace to auto-enable the hardware-watchpoint race detector at process
// startup (schedinit), without needing the program itself to call runtime.SetCPUProfileRate.
// This is a lightweight stand-in for a real `go build -race`-style dedicated flag: -tags hwrace
// uses Go's existing, unmodified build-tag mechanism instead of teaching cmd/go a new flag.

package runtime

const hwraceAutoEnable = true
