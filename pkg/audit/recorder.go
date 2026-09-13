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

// SuppressibleRecorder can decline a low-priority event without turning it into
// a recording failure. Regular Record calls always retain fail-closed semantics.
type SuppressibleRecorder interface {
	Recorder
	RecordSuppressible(context.Context, Event) (bool, error)
}

// SealableRecorder can publish the current non-empty local segment while
// retaining the journal process lock for a bounded remote-delivery flush.
type SealableRecorder interface {
	Recorder
	Seal() error
}
