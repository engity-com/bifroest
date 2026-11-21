package audit

// JournalSpaceObserver allows the service's background observer to sample the
// recorder's actual journal filesystem, without inspecting paths during scrapes.
type JournalSpaceObserver interface {
	JournalAvailableBytes() (uint64, error)
}

func (r *nativeRecorder) JournalAvailableBytes() (uint64, error) {
	// The path is immutable. Do not contend with the journal's persistence lock
	// or use its policy/injected reserve checker for observational work.
	return availableJournalBytes(r.headDirectory)
}
