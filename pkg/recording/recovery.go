package recording

import "io"

const startupRecoveryReason = "startup-recovery"

type RecoveryFile interface {
	io.ReaderAt
	io.Writer
	io.Seeker
	Truncate(size int64) error
	Sync() error
}
