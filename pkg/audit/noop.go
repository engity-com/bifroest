package audit

import "context"

// NewNoopRecorder creates a recorder that discards every event. It is used
// when audit logging is disabled.
func NewNoopRecorder() Recorder {
	return noopRecorder{}
}

type noopRecorder struct{}

func (noopRecorder) Record(context.Context, Event) error {
	return nil
}

func (noopRecorder) RecordSuppressible(context.Context, Event) (bool, error) {
	return true, nil
}

func (noopRecorder) Close() error {
	return nil
}

func (noopRecorder) Seal() error {
	return nil
}
