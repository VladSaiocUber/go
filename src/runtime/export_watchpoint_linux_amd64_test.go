// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file lives in the runtime package (and must not import "testing" —
// that would be an import cycle) so the runtime_test package below can
// reach pickWatchRegion. The actual test is in watchpoint_linux_amd64_test.go.

package runtime

var PickWatchRegion = pickWatchRegion
