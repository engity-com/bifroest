//go:build e2e

package e2e_test

import _ "embed"

// This patch belongs only to the owned Alpine test workload. It is not a
// Bifroest runtime dependency or a terminal-protocol filter.
//
//go:embed testdata/busybox/read-key-cursor.patch
var busyboxCursorPatch []byte
