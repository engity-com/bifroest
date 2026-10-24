package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
)

const AssociationSchema = "bifroest-session-association-v1"

var (
	ErrAssociationUnavailable = errors.New("session associations are unavailable")
	ErrInvalidAssociation     = errors.New("invalid persisted session association; operator inspection required")
	ErrAssociationConflict    = errors.New("session association is immutable")
	ErrAnonymousAssociation   = errors.New("anonymous session reuse requires an independent possession proof")
)

// Target is a versioned digest of server-resolved environment selection, not a
// client-supplied target name, container ID or browser resumption permission.
type Target string

// NewTarget canonically encodes explicit, already-resolved target fields. Callers
// must use the effective target account/backend and configuration, never infer
// them from a principal alone. Do not include credentials, transport IDs or HTTP
// domain/slug unless they actually change the environment selection.
func NewTarget(kind string, fields map[string]string) (Target, error) {
	if kind == "" || len(kind) > 64 || !utf8.ValidString(kind) || len(fields) == 0 || len(fields) > 256 {
		return "", fmt.Errorf("invalid session target descriptor")
	}
	var inputBytes int
	for key, value := range fields {
		if key == "" || len(key) > 128 || len(value) > 16384 || !utf8.ValidString(key) || !utf8.ValidString(value) {
			return "", fmt.Errorf("invalid session target field")
		}
		inputBytes += len(key) + len(value)
		// JSON escaping can expand input by up to six times. Bound allocations
		// before encoding, as well as checking the final canonical representation.
		if inputBytes > 128<<10 {
			return "", fmt.Errorf("session target descriptor is too large")
		}
	}
	raw, err := json.Marshal(struct {
		Schema string            `json:"schema"`
		Kind   string            `json:"kind"`
		Fields map[string]string `json:"fields"`
	}{"bifroest-session-target-v1", kind, fields})
	if err != nil {
		return "", fmt.Errorf("cannot encode session target")
	}
	if len(raw) > 1<<20 {
		return "", fmt.Errorf("session target descriptor is too large")
	}
	digest := sha256.Sum256(raw)
	return Target(hex.EncodeToString(digest[:])), nil
}

func (this Target) Validate() error {
	if len(this) != 64 || strings.ToLower(string(this)) != string(this) {
		return fmt.Errorf("invalid session target digest")
	}
	if _, err := hex.DecodeString(string(this)); err != nil {
		return fmt.Errorf("invalid session target digest")
	}
	return nil
}

// Association is immutable server-side session ownership. The flow is supplied
// by the session's existing path. A configurable display principal deliberately
// does not participate in the identity key. This record is not authentication.
type Association struct {
	Schema  string `json:"schema"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Target  Target `json:"target"`
}

func NewAssociation(identity authentication.Identity, target Target) (Association, error) {
	if err := identity.Validate(); err != nil {
		return Association{}, fmt.Errorf("invalid verified session identity")
	}
	if !identity.IsAuthenticated() {
		return Association{}, ErrAnonymousAssociation
	}
	result := Association{AssociationSchema, identity.Issuer, identity.Subject, target}
	return result, result.Validate()
}

func (this Association) Validate() error {
	if this.Schema != AssociationSchema {
		return ErrInvalidAssociation
	}
	identity := authentication.Identity{Principal: "session-owner", Issuer: this.Issuer, Subject: this.Subject}
	if err := identity.Validate(); err != nil || !identity.IsAuthenticated() {
		return ErrInvalidAssociation
	}
	if this.Target.Validate() != nil {
		return ErrInvalidAssociation
	}
	return nil
}

func (this Association) SameSubject(identity authentication.Identity) bool {
	return this.Validate() == nil && identity.Validate() == nil && identity.IsAuthenticated() && this.Issuer == identity.Issuer && this.Subject == identity.Subject
}

// AssociationProvider is optional, preserving Session implementations and legacy
// records. A nil result denotes an unbound legacy session, never anonymous proof.
type AssociationProvider interface {
	SessionAssociation(context.Context) (*Association, error)
}
type AssociationBinder interface {
	AssociationProvider
	// Binding is allowed only for new, inactive sessions without environment
	// state. It cannot claim an established legacy session by its identifier.
	BindSessionAssociation(context.Context, Association) error
}

func AssociationOf(ctx context.Context, sess Session) (*Association, error) {
	if provider, ok := sess.(AssociationProvider); ok {
		result, err := provider.SessionAssociation(ctx)
		if err != nil || result == nil {
			return nil, err
		}
		if err := result.Validate(); err != nil {
			return nil, err
		}
		copyOfResult := *result
		return &copyOfResult, nil
	}
	return nil, ErrAssociationUnavailable
}

// Reference supplies the candidate session ID for target templates such as a
// Kubernetes pod name containing .session.id. The target resolver is pure: it
// must not provision resources or substitute another requesting user.
type Reference struct {
	Flow configuration.FlowName
	Id   Id
	// Created is immutable persisted creation metadata for an existing candidate,
	// or the exact prospective metadata which creation will persist on success.
	Created InfoCreated
}
type TargetResolver func(context.Context, Reference) (Target, error)

// AssociationRequest is accepted only from a trusted adapter AFTER credential
// verification, never an unsigned SSH key probe or unverified browser payload.
// Authentication remains the caller's responsibility. Remote is unchanged client
// metadata, not an identity key. AuthorizationToken is opaque and is only written
// for newly created sessions, never copied over live OIDC refresh credentials.
type AssociationRequest struct {
	Flow               configuration.FlowName
	Identity           authentication.Identity
	Remote             net.Remote
	AuthorizationToken []byte
	ResolveTarget      TargetResolver
	Compatible         Predicate
}

// AssociatedRepository atomically selects or creates a persistently bound
// session. It does not migrate legacy sessions or mint browser permissions.
type AssociatedRepository interface {
	ResolveAssociatedSession(context.Context, AssociationRequest) (found Session, created bool, err error)
}
