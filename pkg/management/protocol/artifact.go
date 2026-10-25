package protocol

// ArtifactRequest selects original sealed evidence, never server-side decryption
// or credentials. Its selectors and completion assertions are not permissions or
// producer trust anchors. Transport/authentication scopes remain independent.
type ArtifactRequest struct {
	Operation ArtifactOperation `json:"operation" cbor:"1,keyasint"`
	Auditlog  string            `json:"auditlog" cbor:"2,keyasint"`
	ID        string            `json:"id,omitempty" cbor:"3,keyasint"`
}

type ArtifactOperation string

const (
	DownloadRecording             ArtifactOperation = "recordings.download"
	DownloadAudit                 ArtifactOperation = "audit.download"
	MaximumRecordingArtifactBytes int64             = 32 << 30
)

func ValidAuditlogName(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func (this ArtifactRequest) Validate() error {
	if !ValidAuditlogName(this.Auditlog) {
		return ErrRequest
	}
	switch this.Operation {
	case DownloadRecording:
		if !ValidID(this.ID) {
			return ErrRequest
		}
	case DownloadAudit:
		if this.ID != "" {
			return ErrRequest
		}
	default:
		return ErrRequest
	}
	return nil
}
