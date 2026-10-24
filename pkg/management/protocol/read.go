// Package protocol contains portable management data, not CLI, SSH, storage or
// authentication. Selectors/cursors are never permissions to inspect a server.
package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const Version = 1
const MaximumPageSize = 20
const MaximumResponseBytes = 64 << 10
const MaximumCursorBytes = 4096

var ErrRequest = errors.New("invalid structured management request")

type ReadOperation string

const (
	ListFlows    ReadOperation = "flows.list"
	ListSessions ReadOperation = "sessions.list"
	ShowSession  ReadOperation = "sessions.show"
)

type ReadRequest struct {
	Operation ReadOperation `json:"operation"`
	Limit     int           `json:"limit,omitempty"`
	After     string        `json:"after,omitempty"`
	Flow      string        `json:"flow,omitempty"`
	User      string        `json:"user,omitempty"`
	State     string        `json:"state,omitempty"`
	ID        string        `json:"id,omitempty"`
}

func text(value string, maximum int) bool {
	return len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}
func (this ReadRequest) Normalize() (ReadRequest, error) {
	if !text(this.Flow, 255) || !text(this.User, 256) || len(this.After) > MaximumCursorBytes {
		return this, ErrRequest
	}
	switch this.Operation {
	case ListFlows:
		if this.Flow != "" || this.User != "" || this.State != "" || this.ID != "" {
			return this, ErrRequest
		}
	case ListSessions:
		if this.ID != "" {
			return this, ErrRequest
		}
		if this.State == "" {
			this.State = "active"
		}
		switch this.State {
		case "active", "new", "authorized", "disposed", "all":
		default:
			return this, ErrRequest
		}
	case ShowSession:
		if this.Limit != 0 || this.After != "" || this.User != "" || this.State != "" || this.Flow == "" || !ValidID(this.ID) {
			return this, ErrRequest
		}
		return this, nil
	default:
		return this, ErrRequest
	}
	if this.Limit == 0 {
		this.Limit = MaximumPageSize
	}
	if this.Limit < 1 || this.Limit > MaximumPageSize {
		return this, ErrRequest
	}
	if _, _, err := this.Cursor(); err != nil {
		return this, err
	}
	return this, nil
}

func ValidID(value string) bool {
	if len(value) != 36 || value == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

type cursor struct {
	Operation ReadOperation `json:"operation"`
	Filter    [32]byte      `json:"filter"`
	Flow      string        `json:"flow"`
	ID        string        `json:"id"`
}

func (this ReadRequest) Next(flow, id string) string {
	raw, _ := json.Marshal(cursor{this.Operation, this.filter(), flow, id})
	return "bmp1." + base64.RawURLEncoding.EncodeToString(raw)
}

func (this ReadRequest) filter() [32]byte {
	raw, _ := json.Marshal(struct{ Flow, User, State string }{this.Flow, this.User, this.State})
	return sha256.Sum256(raw)
}

func (this ReadRequest) Cursor() (string, string, error) {
	if this.After == "" {
		return "", "", nil
	}
	if len(this.After) > MaximumCursorBytes || !strings.HasPrefix(this.After, "bmp1.") {
		return "", "", ErrRequest
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(this.After[5:])
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != this.After[5:] {
		return "", "", ErrRequest
	}
	var selected cursor
	if json.Unmarshal(raw, &selected) != nil {
		return "", "", ErrRequest
	}
	canonical, err := json.Marshal(selected)
	if err != nil || string(canonical) != string(raw) || selected.Operation != this.Operation || selected.Filter != this.filter() || selected.Flow == "" || !text(selected.Flow, 255) {
		return "", "", ErrRequest
	}
	if this.Operation == ListFlows {
		if selected.ID != "" {
			return "", "", ErrRequest
		}
	} else if this.Operation != ListSessions || !ValidID(selected.ID) {
		return "", "", ErrRequest
	}
	return selected.Flow, selected.ID, nil
}

type FlowSummary struct {
	Name          string `json:"name" yaml:"name"`
	Auditlog      string `json:"auditlog" yaml:"auditlog"`
	Authorization string `json:"authorization" yaml:"authorization"`
	Environment   string `json:"environment" yaml:"environment"`
}

// User/Remote are original requesting metadata, not a verified display principal.
type SessionView struct {
	ID           string     `json:"id" yaml:"id"`
	Flow         string     `json:"flow" yaml:"flow"`
	State        string     `json:"state" yaml:"state"`
	User         string     `json:"user" yaml:"user"`
	Remote       string     `json:"remote" yaml:"remote"`
	CreatedAt    time.Time  `json:"createdAt" yaml:"createdAt"`
	LastAccessed *time.Time `json:"lastAccessed,omitempty" yaml:"lastAccessed,omitempty"`
	ValidUntil   *time.Time `json:"validUntil,omitempty" yaml:"validUntil,omitempty"`
}

// Owner is immutable verified issuer/subject evidence, not a mapped principal or
// a saved rights snapshot. Legacy/anonymous sessions have no such association.
type Owner struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}
type SessionItem struct {
	SessionView
	Owner         *Owner `json:"owner"`
	PolicyLimited bool   `json:"policyLimited,omitempty"`
}
type Page[T any] struct {
	Items   []T    `json:"items"`
	Next    string `json:"next"`
	Skipped int    `json:"skipped"`
}
type ReadResult struct {
	Version   int                `json:"version"`
	Operation ReadOperation      `json:"operation"`
	Flows     *Page[FlowSummary] `json:"flows,omitempty"`
	Sessions  *Page[SessionItem] `json:"sessions,omitempty"`
	Session   *SessionItem       `json:"session,omitempty"`
}
