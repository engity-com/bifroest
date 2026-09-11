package authorization

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
)

const (
	AuthorizationEvidenceSchema        = "bifroest.authorization-evidence/v1"
	AuthorizationEvidenceExtension     = "evidence-v1@bifroest.engity.org"
	BifroestDelegationCriticalOption   = "bifroest-delegation@bifroest.engity.org"
	MaxAuthorizationEvidenceSize       = 4 * 1024
	MaxAuthorizationEvidenceHops       = 8
	maxAuthorizationEvidenceStringSize = 1024
	maxAuthorizationEvidenceClockSkew  = 30 * time.Second
)

type AuthorizationEvidence struct {
	Schema string                      `json:"schema"`
	Origin AuthorizationEvidenceOrigin `json:"origin"`
	Hops   []AuthorizationEvidenceHop  `json:"hops"`
}

type AuthorizationEvidenceOrigin struct {
	User              string `json:"user"`
	Host              string `json:"host"`
	AuthorizationKind string `json:"authorizationKind"`
}

func (this AuthorizationEvidenceOrigin) GetField(name string) (any, bool, error) {
	switch name {
	case "user":
		return this.User, true, nil
	case "host":
		return this.Host, true, nil
	case "authorizationKind":
		return this.AuthorizationKind, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

type AuthorizationEvidenceHop struct {
	CaFingerprint          string    `json:"caFingerprint"`
	SubjectKeyFingerprint  string    `json:"subjectKeyFingerprint"`
	Serial                 uint64    `json:"serial"`
	KeyId                  string    `json:"keyId"`
	SessionId              string    `json:"sessionId"`
	Flow                   string    `json:"flow"`
	AuthorizationKind      string    `json:"authorizationKind"`
	Audience               string    `json:"audience,omitempty"`
	TargetUser             string    `json:"targetUser"`
	IssuedAt               time.Time `json:"issuedAt"`
	ValidAfter             time.Time `json:"validAfter"`
	ValidBefore            time.Time `json:"validBefore"`
	PtyAllowed             bool      `json:"ptyAllowed"`
	PortForwardingAllowed  bool      `json:"portForwardingAllowed"`
	AgentForwardingAllowed bool      `json:"agentForwardingAllowed"`
}

func (this AuthorizationEvidenceHop) GetField(name string) (any, bool, error) {
	switch name {
	case "caFingerprint":
		return this.CaFingerprint, true, nil
	case "subjectKeyFingerprint":
		return this.SubjectKeyFingerprint, true, nil
	case "serial":
		return this.Serial, true, nil
	case "keyId":
		return this.KeyId, true, nil
	case "sessionId":
		return this.SessionId, true, nil
	case "flow":
		return this.Flow, true, nil
	case "authorizationKind":
		return this.AuthorizationKind, true, nil
	case "audience":
		return this.Audience, true, nil
	case "targetUser":
		return this.TargetUser, true, nil
	case "issuedAt":
		return this.IssuedAt, true, nil
	case "validAfter":
		return this.ValidAfter, true, nil
	case "validBefore":
		return this.ValidBefore, true, nil
	case "ptyAllowed":
		return this.PtyAllowed, true, nil
	case "portForwardingAllowed":
		return this.PortForwardingAllowed, true, nil
	case "agentForwardingAllowed":
		return this.AgentForwardingAllowed, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

type AuthorizationEvidencePolicy struct {
	PtyAllowed             bool `json:"ptyAllowed"`
	PortForwardingAllowed  bool `json:"portForwardingAllowed"`
	AgentForwardingAllowed bool `json:"agentForwardingAllowed"`
}

func (this AuthorizationEvidencePolicy) GetField(name string) (any, bool, error) {
	switch name {
	case "ptyAllowed":
		return this.PtyAllowed, true, nil
	case "portForwardingAllowed":
		return this.PortForwardingAllowed, true, nil
	case "agentForwardingAllowed":
		return this.AgentForwardingAllowed, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

type AuthorizationEvidenceProvider interface {
	AuthorizationEvidence() *AuthorizationEvidence
}

func AuthorizationEvidenceOf(auth Authorization) *AuthorizationEvidence {
	provider, ok := auth.(AuthorizationEvidenceProvider)
	if !ok {
		return nil
	}
	return provider.AuthorizationEvidence()
}

func (this *AuthorizationEvidence) Clone() *AuthorizationEvidence {
	if this == nil {
		return nil
	}
	result := *this
	result.Hops = append([]AuthorizationEvidenceHop(nil), this.Hops...)
	return &result
}

func (this *AuthorizationEvidence) LastHop() *AuthorizationEvidenceHop {
	if this == nil || len(this.Hops) == 0 {
		return nil
	}
	result := this.Hops[len(this.Hops)-1]
	return &result
}

func (this *AuthorizationEvidence) Policy() AuthorizationEvidencePolicy {
	last := this.LastHop()
	if last == nil {
		return AuthorizationEvidencePolicy{}
	}
	return AuthorizationEvidencePolicy{
		PtyAllowed:             last.PtyAllowed,
		PortForwardingAllowed:  last.PortForwardingAllowed,
		AgentForwardingAllowed: last.AgentForwardingAllowed,
	}
}

func (this *AuthorizationEvidence) Append(hop AuthorizationEvidenceHop) error {
	if this == nil {
		return fmt.Errorf("authorization evidence is absent")
	}
	this.Hops = append(this.Hops, normalizeAuthorizationEvidenceHop(hop))
	if err := this.Validate(); err != nil {
		this.Hops = this.Hops[:len(this.Hops)-1]
		return err
	}
	return nil
}

func (this *AuthorizationEvidence) Validate() error {
	if this == nil {
		return fmt.Errorf("authorization evidence is absent")
	}
	if this.Schema != AuthorizationEvidenceSchema {
		return fmt.Errorf("unsupported authorization evidence schema %q", this.Schema)
	}
	if err := validateAuthorizationEvidenceString("origin.user", this.Origin.User, true); err != nil {
		return err
	}
	if err := validateAuthorizationEvidenceString("origin.host", this.Origin.Host, true); err != nil {
		return err
	}
	if err := validateAuthorizationEvidenceString("origin.authorizationKind", this.Origin.AuthorizationKind, true); err != nil {
		return err
	}
	if len(this.Hops) == 0 {
		return fmt.Errorf("authorization evidence does not contain a hop")
	}
	if len(this.Hops) > MaxAuthorizationEvidenceHops {
		return fmt.Errorf("authorization evidence exceeds %d hops", MaxAuthorizationEvidenceHops)
	}

	seenSubjects := make(map[string]int, len(this.Hops))
	for i := range this.Hops {
		hop := &this.Hops[i]
		for name, value := range map[string]string{
			"caFingerprint": hop.CaFingerprint, "subjectKeyFingerprint": hop.SubjectKeyFingerprint,
			"keyId": hop.KeyId, "sessionId": hop.SessionId, "flow": hop.Flow,
			"authorizationKind": hop.AuthorizationKind, "targetUser": hop.TargetUser,
		} {
			if err := validateAuthorizationEvidenceString(fmt.Sprintf("hops[%d].%s", i, name), value, true); err != nil {
				return err
			}
		}
		if err := validateAuthorizationEvidenceString(fmt.Sprintf("hops[%d].audience", i), hop.Audience, false); err != nil {
			return err
		}
		if err := validateAuthorizationEvidenceFingerprint(hop.CaFingerprint); err != nil {
			return fmt.Errorf("authorization evidence hops[%d].caFingerprint is invalid: %w", i, err)
		}
		if err := validateAuthorizationEvidenceFingerprint(hop.SubjectKeyFingerprint); err != nil {
			return fmt.Errorf("authorization evidence hops[%d].subjectKeyFingerprint is invalid: %w", i, err)
		}
		parsedSessionId, err := uuid.Parse(hop.SessionId)
		if err != nil {
			return fmt.Errorf("authorization evidence hops[%d].sessionId is invalid: %w", i, err)
		}
		if parsedSessionId == uuid.Nil || parsedSessionId.String() != hop.SessionId {
			return fmt.Errorf("authorization evidence hops[%d].sessionId is invalid", i)
		}
		flow := configuration.FlowName(hop.Flow)
		if err := flow.Validate(); err != nil {
			return fmt.Errorf("authorization evidence hops[%d].flow is invalid: %w", i, err)
		}
		if hop.Serial == 0 {
			return fmt.Errorf("authorization evidence hops[%d].serial is zero", i)
		}
		if hop.IssuedAt.IsZero() || hop.ValidAfter.IsZero() || hop.ValidBefore.IsZero() {
			return fmt.Errorf("authorization evidence hops[%d] has incomplete timestamps", i)
		}
		if hop.ValidAfter.After(hop.IssuedAt) || !hop.ValidBefore.After(hop.IssuedAt) {
			return fmt.Errorf("authorization evidence hops[%d] has illegal validity boundaries", i)
		}
		if previous, exists := seenSubjects[hop.SubjectKeyFingerprint]; exists {
			return fmt.Errorf("authorization evidence hops[%d].subjectKeyFingerprint duplicates hops[%d]", i, previous)
		}
		seenSubjects[hop.SubjectKeyFingerprint] = i
		if i == 0 && hop.AuthorizationKind != this.Origin.AuthorizationKind {
			return fmt.Errorf("authorization evidence first hop does not match the origin authorization kind")
		}
		if i > 0 {
			previous := this.Hops[i-1]
			if hop.AuthorizationKind != "bifroest" {
				return fmt.Errorf("authorization evidence hops[%d] is not a Bifroest delegation", i)
			}
			if hop.ValidAfter.Before(previous.ValidAfter) {
				return fmt.Errorf("authorization evidence hops[%d] extends the previous valid-after boundary", i)
			}
			if hop.ValidBefore.After(previous.ValidBefore) {
				return fmt.Errorf("authorization evidence hops[%d] extends the previous validity", i)
			}
			if hop.PtyAllowed && !previous.PtyAllowed ||
				hop.PortForwardingAllowed && !previous.PortForwardingAllowed ||
				hop.AgentForwardingAllowed && !previous.AgentForwardingAllowed {
				return fmt.Errorf("authorization evidence hops[%d] extends previous capabilities", i)
			}
		}
	}
	return nil
}

func EncodeAuthorizationEvidence(evidence *AuthorizationEvidence) ([]byte, error) {
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	normalized := evidence.Clone()
	normalized.Origin.User = strings.TrimSpace(normalized.Origin.User)
	normalized.Origin.Host = strings.TrimSpace(normalized.Origin.Host)
	normalized.Origin.AuthorizationKind = strings.TrimSpace(normalized.Origin.AuthorizationKind)
	for i := range normalized.Hops {
		normalized.Hops[i] = normalizeAuthorizationEvidenceHop(normalized.Hops[i])
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("cannot encode authorization evidence: %w", err)
	}
	if len(raw) > MaxAuthorizationEvidenceSize {
		return nil, fmt.Errorf("authorization evidence exceeds %d bytes", MaxAuthorizationEvidenceSize)
	}
	return raw, nil
}

func DecodeAuthorizationEvidence(raw []byte) (*AuthorizationEvidence, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("authorization evidence is empty")
	}
	if len(raw) > MaxAuthorizationEvidenceSize {
		return nil, fmt.Errorf("authorization evidence exceeds %d bytes", MaxAuthorizationEvidenceSize)
	}
	if err := rejectDuplicateAuthorizationEvidenceFields(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result AuthorizationEvidence
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("cannot decode authorization evidence: %w", err)
	}
	if err := ensureAuthorizationEvidenceJSONEnd(decoder); err != nil {
		return nil, err
	}
	if err := result.Validate(); err != nil {
		return nil, err
	}
	canonical, err := EncodeAuthorizationEvidence(&result)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, canonical) {
		return nil, fmt.Errorf("authorization evidence is not canonically encoded")
	}
	return &result, nil
}

func ValidateBifroestDelegationEvidence(evidence *AuthorizationEvidence, certificate *ssh.Certificate, username string, audiences []string, maxValidity time.Duration, now time.Time) (*AuthorizedKeyPolicy, error) {
	policy, err := ValidateAuthorizationEvidenceCertificate(evidence, certificate, username, now)
	if err != nil {
		return nil, err
	}
	last := evidence.LastHop()
	if last == nil || last.Audience == "" || !slices.Contains(audiences, last.Audience) {
		return nil, fmt.Errorf("authorization evidence audience %q is not accepted", lastAudience(last))
	}
	if evidence.Origin.AuthorizationKind == "none" {
		return nil, fmt.Errorf("authorization evidence has an unauthenticated origin")
	}
	validAfter := last.ValidAfter
	validBefore := last.ValidBefore
	if last.IssuedAt.After(now.Add(maxAuthorizationEvidenceClockSkew)) || last.IssuedAt.Before(validAfter) || !last.IssuedAt.Before(validBefore) {
		return nil, fmt.Errorf("authorization evidence issuance time is outside of the certificate validity")
	}
	if maxValidity <= 0 || validBefore.Sub(last.IssuedAt) > maxValidity {
		return nil, fmt.Errorf("SSH certificate exceeds the maximum validity of %s", maxValidity)
	}
	return policy, nil
}

func ValidateAuthorizationEvidenceCertificate(evidence *AuthorizationEvidence, certificate *ssh.Certificate, username string, now time.Time) (*AuthorizedKeyPolicy, error) {
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	if certificate == nil {
		return nil, fmt.Errorf("SSH user certificate is absent")
	}
	if certificate.Key == nil || certificate.SignatureKey == nil {
		return nil, fmt.Errorf("SSH user certificate has incomplete key material")
	}
	last := evidence.LastHop()
	validAfter, err := sshCertificateTime(certificate.ValidAfter)
	if err != nil {
		return nil, fmt.Errorf("certificate valid-after is invalid: %w", err)
	}
	validBefore, err := sshCertificateTime(certificate.ValidBefore)
	if err != nil {
		return nil, fmt.Errorf("certificate valid-before is invalid: %w", err)
	}
	if last.CaFingerprint != ssh.FingerprintSHA256(certificate.SignatureKey) ||
		last.SubjectKeyFingerprint != ssh.FingerprintSHA256(certificate.Key) ||
		last.Serial != certificate.Serial || last.KeyId != certificate.KeyId ||
		last.TargetUser != username || !last.ValidAfter.Equal(validAfter) || !last.ValidBefore.Equal(validBefore) {
		return nil, fmt.Errorf("authorization evidence does not match its SSH certificate")
	}
	if len(certificate.Nonce) == 0 {
		return nil, fmt.Errorf("SSH certificate nonce is absent")
	}
	if last.IssuedAt.After(now.Add(maxAuthorizationEvidenceClockSkew)) || last.IssuedAt.Before(validAfter) || !last.IssuedAt.Before(validBefore) {
		return nil, fmt.Errorf("authorization evidence issuance time is outside of the certificate validity")
	}
	policy, err := authorizedKeyPolicyForCertificate(nil, certificate)
	if err != nil {
		return nil, err
	}
	if last.PtyAllowed != policy.PtyAllowed || last.PortForwardingAllowed != policy.PortForwardingAllowed || last.AgentForwardingAllowed != policy.AgentForwardingAllowed {
		return nil, fmt.Errorf("authorization evidence capabilities do not match the SSH certificate")
	}
	return policy, nil
}

func normalizeAuthorizationEvidenceHop(hop AuthorizationEvidenceHop) AuthorizationEvidenceHop {
	hop.CaFingerprint = strings.TrimSpace(hop.CaFingerprint)
	hop.SubjectKeyFingerprint = strings.TrimSpace(hop.SubjectKeyFingerprint)
	hop.KeyId = strings.TrimSpace(hop.KeyId)
	hop.SessionId = strings.TrimSpace(hop.SessionId)
	hop.Flow = strings.TrimSpace(hop.Flow)
	hop.AuthorizationKind = strings.TrimSpace(hop.AuthorizationKind)
	hop.Audience = strings.TrimSpace(hop.Audience)
	hop.TargetUser = strings.TrimSpace(hop.TargetUser)
	hop.IssuedAt = hop.IssuedAt.UTC().Truncate(time.Second)
	hop.ValidAfter = hop.ValidAfter.UTC().Truncate(time.Second)
	hop.ValidBefore = hop.ValidBefore.UTC().Truncate(time.Second)
	return hop
}

func validateAuthorizationEvidenceString(name, value string, required bool) error {
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("authorization evidence %s is empty", name)
	}
	if len(value) > maxAuthorizationEvidenceStringSize || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("authorization evidence %s is illegal", name)
	}
	return nil
}

func validateAuthorizationEvidenceFingerprint(value string) error {
	const prefix = "SHA256:"
	if !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("expected an SHA256 fingerprint")
	}
	encoded := strings.TrimPrefix(value, prefix)
	raw, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != 32 || base64.RawStdEncoding.EncodeToString(raw) != encoded {
		return fmt.Errorf("expected an SHA256 fingerprint")
	}
	return nil
}

func sshCertificateTime(value uint64) (time.Time, error) {
	if value == ssh.CertTimeInfinity || value > math.MaxInt64 {
		return time.Time{}, fmt.Errorf("unsupported infinite or out-of-range value")
	}
	return time.Unix(int64(value), 0).UTC(), nil
}

func lastAudience(hop *AuthorizationEvidenceHop) string {
	if hop == nil {
		return ""
	}
	return hop.Audience
}

func rejectDuplicateAuthorizationEvidenceFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := readUniqueAuthorizationEvidenceJSONValue(decoder); err != nil {
		return fmt.Errorf("cannot decode authorization evidence: %w", err)
	}
	return ensureAuthorizationEvidenceJSONEnd(decoder)
}

func readUniqueAuthorizationEvidenceJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := readUniqueAuthorizationEvidenceJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("object is not terminated")
		}
	case '[':
		for decoder.More() {
			if err := readUniqueAuthorizationEvidenceJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("array is not terminated")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func ensureAuthorizationEvidenceJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("authorization evidence contains a second JSON value")
		}
		return fmt.Errorf("authorization evidence has trailing data: %w", err)
	}
	return nil
}
