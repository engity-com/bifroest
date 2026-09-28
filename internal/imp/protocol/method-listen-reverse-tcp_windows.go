//go:build windows

package protocol

func authorizeReverseTCPPort(_ uint16, _ string, _ bool) error {
	return nil
}
