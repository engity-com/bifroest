//go:build unix

package audit

import "os"

func openVerifierPath(path string) (*os.File, error) { return os.Open(path) }
