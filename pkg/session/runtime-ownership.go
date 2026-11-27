package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/engity-com/bifroest/pkg/configuration"
)

const (
	RuntimeStateSchema     = "bifroest-runtime-state-v1"
	RuntimeOwnershipSchema = "bifroest-session-runtime-ownership-v1"
	MaximumRuntimeFlows    = 4096
)

var (
	ErrInvalidRuntimeState         = errors.New("invalid persisted runtime state; operator inspection required")
	ErrInvalidRuntimeOwnership     = errors.New("invalid persisted session runtime ownership; operator inspection required")
	ErrRuntimeStateConflict        = errors.New("persisted runtime state has changed")
	ErrRuntimeOwnershipUnavailable = errors.New("session runtime ownership is unavailable")
)

// RuntimeRevision is an opaque random identity, not a content digest. Reverting
// to earlier values must not revive a removed flow or an older environment.
type RuntimeRevision string

func NewRuntimeRevision() (RuntimeRevision, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	revision := RuntimeRevision(hex.EncodeToString(value[:]))
	return revision, revision.Validate()
}

func validRuntimeHex(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	for _, b := range raw {
		if b != 0 {
			return true
		}
	}
	return false
}

func (this RuntimeRevision) Validate() error {
	if !validRuntimeHex(string(this)) {
		return ErrInvalidRuntimeState
	}
	return nil
}

// RuntimeFlow stores identities and keyed comparisons only, never provider
// definitions, credentials or a replacement for fresh authentication.
type RuntimeFlow struct {
	Incarnation       RuntimeRevision `json:"incarnation"`
	Environment       RuntimeRevision `json:"environment"`
	Owner             RuntimeRevision `json:"owner"`
	EnvironmentDigest string          `json:"environmentDigest"`
	OwnerDigest       string          `json:"ownerDigest"`
}

func (this RuntimeFlow) Validate() error {
	if this.Incarnation.Validate() != nil || this.Environment.Validate() != nil || this.Owner.Validate() != nil ||
		!validRuntimeHex(this.EnvironmentDigest) || !validRuntimeHex(this.OwnerDigest) {
		return ErrInvalidRuntimeState
	}
	return nil
}

type RuntimeState struct {
	Schema   string                                 `json:"schema"`
	Revision RuntimeRevision                        `json:"revision"`
	Flows    map[configuration.FlowName]RuntimeFlow `json:"flows"`
}

// AdvanceRuntimeState is pure preparation: it performs no storage write and
// cannot activate a candidate. Keep identities only from the immediately
// preceding state; removed/recreated flows and reverted values get fresh IDs.
func AdvanceRuntimeState(previous *RuntimeState, digests map[configuration.FlowName]configuration.RuntimeFlowDigests) (*RuntimeState, error) {
	if previous != nil && previous.Validate() != nil || digests == nil || len(digests) > MaximumRuntimeFlows {
		return nil, ErrInvalidRuntimeState
	}
	revision, err := NewRuntimeRevision()
	if err != nil {
		return nil, err
	}
	result := &RuntimeState{Schema: RuntimeStateSchema, Revision: revision, Flows: make(map[configuration.FlowName]RuntimeFlow, len(digests))}
	for name, next := range digests {
		if name.Validate() != nil || !validRuntimeHex(next.Environment) || !validRuntimeHex(next.Owner) {
			return nil, ErrInvalidRuntimeState
		}
		var flow RuntimeFlow
		if previous != nil {
			flow = previous.Flows[name]
		}
		if flow.Incarnation == "" {
			if flow.Incarnation, err = NewRuntimeRevision(); err != nil {
				return nil, err
			}
		}
		if flow.Environment == "" || flow.EnvironmentDigest != next.Environment {
			if flow.Environment, err = NewRuntimeRevision(); err != nil {
				return nil, err
			}
			// Environment changes always invalidate the owning provider revision.
			flow.Owner = ""
		}
		if flow.Owner == "" || flow.OwnerDigest != next.Owner {
			if flow.Owner, err = NewRuntimeRevision(); err != nil {
				return nil, err
			}
		}
		flow.EnvironmentDigest, flow.OwnerDigest = next.Environment, next.Owner
		result.Flows[name] = flow
	}
	return result, nil
}

func (this RuntimeState) Validate() error {
	if this.Schema != RuntimeStateSchema || this.Revision.Validate() != nil || this.Flows == nil || len(this.Flows) > MaximumRuntimeFlows {
		return ErrInvalidRuntimeState
	}
	for name, flow := range this.Flows {
		if name.Validate() != nil || flow.Validate() != nil {
			return ErrInvalidRuntimeState
		}
	}
	return nil
}

// RuntimeCommit distinguishes failure before publication from an error after
// atomic replacement (for example directory fsync). Published MUST NOT be
// treated as rejection or permission to roll back an admission decision.
type RuntimeCommit struct {
	Published bool
	// Uncertain requires stopping admission and operator inspection; neither
	// the previous nor the candidate revision may be assumed authoritative.
	Uncertain bool
	Err       error
}

type RuntimeRepository interface {
	RuntimeKey(context.Context) ([]byte, error)
	RuntimeState(context.Context) (*RuntimeState, error)
	// Empty expected denotes an absent initial state. Each successful update
	// needs a fresh Revision, even when only changing back to earlier values.
	CommitRuntimeState(context.Context, RuntimeRevision, RuntimeState) RuntimeCommit
}

type RuntimeOwnership struct {
	Schema      string                 `json:"schema"`
	Flow        configuration.FlowName `json:"flow"`
	SessionID   Id                     `json:"sessionId"`
	Incarnation RuntimeRevision        `json:"incarnation"`
	Environment RuntimeRevision        `json:"environment"`
	Owner       RuntimeRevision        `json:"owner"`
}

func (this RuntimeOwnership) Validate() error {
	if this.Schema != RuntimeOwnershipSchema || this.Flow.Validate() != nil || this.SessionID.IsZero() ||
		this.Incarnation.Validate() != nil || this.Environment.Validate() != nil || this.Owner.Validate() != nil {
		return ErrInvalidRuntimeOwnership
	}
	return nil
}

func (this RuntimeOwnership) Matches(flow RuntimeFlow) bool {
	return this.Validate() == nil && flow.Validate() == nil &&
		this.Incarnation == flow.Incarnation && this.Environment == flow.Environment && this.Owner == flow.Owner
}

// Ownership has no setter/import operation: only initial creation can assign it.
// Missing legacy ownership must never be guessed from a later configuration.
type RuntimeOwnershipSession interface {
	RuntimeOwnership(context.Context) (*RuntimeOwnership, error)
	RuntimeRevoked(context.Context) (bool, error)
}

type RuntimeSessionRevoker interface {
	RevokeRuntimeSession(context.Context, configuration.FlowName, Id) error
}

type runtimeOwnershipContextKey struct{}

// WithRuntimeOwnership is for trusted server-side creation only. The repository
// binds Flow and SessionID itself, atomically with initial session publication.
func WithRuntimeOwnership(ctx context.Context, flow RuntimeFlow) context.Context {
	return context.WithValue(ctx, runtimeOwnershipContextKey{}, flow)
}
