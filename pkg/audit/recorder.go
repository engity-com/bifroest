package audit

import (
	"context"
	"io"
)

// Recorder persists audit events according to the configured durability and
// failure policy.
type Recorder interface {
	Record(context.Context, Event) error
	io.Closer
}

// SealableRecorder can publish the current non-empty local segment while
// retaining the journal process lock for a bounded remote-delivery flush.
type SealableRecorder interface {
	Recorder
	Seal() error
}
