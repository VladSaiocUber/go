// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !hwrace

// The default: hardware-watchpoint race sampling stays opt-in (via the program itself calling
// runtime.SetCPUProfileRate) unless built with -tags hwrace. See hwrace_on.go.

package runtime

const hwraceAutoEnable = false
