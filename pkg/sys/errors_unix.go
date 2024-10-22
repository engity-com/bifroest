//go:build unix

package sys

func isClosedError(err error) bool {
	return false
}
