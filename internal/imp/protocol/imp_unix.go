//go:build unix && !darwin

package protocol

const (
	DefaultExitCodeByConnectionIdPath = DefaultExitCodeByConnectionIdPathUnix
)
