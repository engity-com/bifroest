package configuration

import "fmt"

// Snapshot owns an isolated, validated configuration. Its data is never exposed
// directly: Configuration returns another copy, including mutable provider data.
// Snapshots can therefore be shared between admissions and reload preparation.
type Snapshot struct {
	configuration Configuration
}

// NewSnapshot does not trim, reapply defaults or serialize configuration secrets.
// YAML loading already normalizes its data; a valid programmatic configuration
// must not be reinterpreted while taking an ownership snapshot.
func NewSnapshot(conf Configuration) (*Snapshot, error) {
	candidate := cloneConfigurationValue(conf)
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("cannot prepare configuration snapshot: %w", err)
	}
	return &Snapshot{configuration: candidate}, nil
}

// Configuration returns an independently mutable copy. In particular, resolving
// references or changing a returned provider cannot mutate this snapshot.
func (this *Snapshot) Configuration() Configuration {
	return cloneConfigurationValue(this.configuration)
}
