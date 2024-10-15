//go:build unix

package net

func isClosedError(err error) bool {
	return false
}
