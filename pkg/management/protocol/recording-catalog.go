package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

var recordingTimePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$`)

// RecordingTime accepts bounded UTC RFC3339 timestamps, not permissive browser
// date strings or normalized impossible calendar dates. Both ends are inclusive.
func RecordingTime(value string) (time.Time, error) {
	if len(value) < 20 || len(value) > 30 || !recordingTimePattern.MatchString(value) {
		return time.Time{}, ErrRequest
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Year() < 1970 || parsed.Year() > 9999 {
		return time.Time{}, ErrRequest
	}
	return parsed, nil
}

// RecordingPageCursor carries positions, never permissions. The application
// authenticates its MAC, live actor/scope and expiry after authorization.
type RecordingPageCursor struct {
	Auditlog     string   `json:"auditlog"`
	Filter       [32]byte `json:"filter"`
	ActorFlow    string   `json:"actorFlow"`
	ActorSession string   `json:"actorSession"`
	StartedAt    string   `json:"startedAt"`
	ID           string   `json:"id"`
	Expires      int64    `json:"expires"`
	MAC          string   `json:"mac"`
}

func (this ReadRequest) RecordingFilter() [32]byte {
	this.After = ""
	raw, _ := json.Marshal(this)
	return sha256.Sum256(raw)
}

func (this RecordingPageCursor) Payload() []byte {
	this.MAC = ""
	raw, _ := json.Marshal(this)
	return raw
}

func (this RecordingPageCursor) Token() string {
	raw, _ := json.Marshal(this)
	return "bmp1." + base64.RawURLEncoding.EncodeToString(raw)
}

func (this ReadRequest) RecordingCursor() (RecordingPageCursor, error) {
	var result RecordingPageCursor
	if this.Operation != ListRecordings || len(this.After) > MaximumCursorBytes || !strings.HasPrefix(this.After, "bmp1.") {
		return result, ErrRequest
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(this.After[5:])
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Token() != this.After ||
		result.Auditlog != this.Auditlog || result.Filter != this.RecordingFilter() ||
		!text(result.ActorFlow, 255) || result.ActorFlow == "" || !ValidID(result.ActorSession) ||
		!ValidID(result.ID) || result.Expires <= 0 {
		return result, ErrRequest
	}
	if _, err := RecordingTime(result.StartedAt); err != nil {
		return result, ErrRequest
	}
	mac, err := base64.RawURLEncoding.Strict().DecodeString(result.MAC)
	if err != nil || len(mac) != sha256.Size || base64.RawURLEncoding.EncodeToString(mac) != result.MAC {
		return result, ErrRequest
	}
	return result, nil
}
