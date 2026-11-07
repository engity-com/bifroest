package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// AuditEventSummary is server-reported operational data, not journal evidence.
type AuditEventSummary struct {
	Key        string         `json:"key"`
	ID         string         `json:"id"`
	RecordedAt time.Time      `json:"recordedAt"`
	Event      map[string]any `json:"event"`
}
type AuditEventSource struct {
	Auditlog     string `json:"auditlog"`
	Encrypted    bool   `json:"encrypted"`
	Sensitive    bool   `json:"sensitive"`
	Verification string `json:"verification"`
}
type CatalogVerification struct {
	Auditlog    string `json:"auditlog"`
	Checked     uint64 `json:"checked"`
	Full        uint64 `json:"full"`
	Outer       uint64 `json:"outer"`
	Independent bool   `json:"independent"`
}
type AuditEventPageCursor struct {
	Auditlog     string   `json:"auditlog"`
	Filter       [32]byte `json:"filter"`
	ActorFlow    string   `json:"actorFlow"`
	ActorSession string   `json:"actorSession"`
	RecordedAt   string   `json:"recordedAt"`
	Sequence     uint64   `json:"sequence"`
	Index        uint64   `json:"index"`
	ID           string   `json:"id"`
	Expires      int64    `json:"expires"`
	MAC          string   `json:"mac"`
}

func (r ReadRequest) AuditEventFilter() [32]byte {
	r.After = ""
	r.Limit = 0
	raw, _ := json.Marshal(r)
	return sha256.Sum256(raw)
}
func (c AuditEventPageCursor) Payload() []byte { c.MAC = ""; raw, _ := json.Marshal(c); return raw }
func (c AuditEventPageCursor) Token() string {
	raw, _ := json.Marshal(c)
	return "bae1." + base64.RawURLEncoding.EncodeToString(raw)
}
func (r ReadRequest) AuditEventCursor() (AuditEventPageCursor, error) {
	var c AuditEventPageCursor
	if r.Operation != ListAuditEvents || len(r.After) > MaximumCursorBytes || !strings.HasPrefix(r.After, "bae1.") {
		return c, ErrRequest
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(r.After[5:])
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Token() != r.After || c.Auditlog != r.Auditlog || c.Filter != r.AuditEventFilter() || !text(c.ActorFlow, 255) || c.ActorFlow == "" || !ValidID(c.ActorSession) || !ValidID(c.ID) || c.Sequence < 1 || c.Sequence > (1<<53)-1 || c.Index > (1<<53)-1 || c.Expires < 1 {
		return c, ErrRequest
	}
	if _, err := RecordingTime(c.RecordedAt); err != nil {
		return c, err
	}
	mac, err := base64.RawURLEncoding.Strict().DecodeString(c.MAC)
	if err != nil || len(mac) != 32 || base64.RawURLEncoding.EncodeToString(mac) != c.MAC {
		return c, ErrRequest
	}
	return c, nil
}
