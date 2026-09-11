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
