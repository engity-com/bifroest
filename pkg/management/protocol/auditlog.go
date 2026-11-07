package protocol

// AuditlogSummary is configuration metadata, not evidence or a signing trust pin.
// It contains no paths, keys, targets, credentials or client decryption material.
type AuditlogSummary struct {
	Name             string `json:"name" yaml:"name"`
	Enabled          bool   `json:"enabled" yaml:"enabled"`
	RecordingEnabled bool   `json:"recordingEnabled" yaml:"recordingEnabled"`
	Encrypted        bool   `json:"encrypted" yaml:"encrypted"`
}
