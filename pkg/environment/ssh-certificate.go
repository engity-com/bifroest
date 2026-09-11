package environment

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	bfssh "github.com/engity-com/bifroest/pkg/ssh"
)

const sshUserCertificateSchema = "bifroest.ssh-user-certificate/v1"

var sshUserCertificateMetadataExtensions = map[string]struct{}{
	authorization.AuthorizationEvidenceExtension: {},
}

type sshCertificateKeys struct {
	subject              gossh.Signer
	subjectIdentityFile  string
	subjectFingerprint   string
	authority            gossh.Signer
	authorityFingerprint string
	configurationKey     string
}

type sshCertificateSpec struct {
	validity          time.Duration
	validAfterSkew    time.Duration
	principals        []string
	extensions        map[string]string
	authorizationKind string
	audience          string
	parentEvidence    *authorization.AuthorizationEvidence
	parentDigest      string
	maxValidBefore    time.Time
}

type sshUserCertificateState struct {
	Schema                string            `json:"schema"`
	State                 string            `json:"state"`
	SessionId             string            `json:"sessionId"`
	Flow                  string            `json:"flow"`
	TargetAddress         string            `json:"targetAddress"`
	TargetUser            string            `json:"targetUser"`
	SubjectKeyFingerprint string            `json:"subjectKeyFingerprint"`
	CaFingerprint         string            `json:"caFingerprint"`
	Serial                uint64            `json:"serial"`
	KeyId                 string            `json:"keyId"`
	IssuedAt              time.Time         `json:"issuedAt"`
	ValidAfter            time.Time         `json:"validAfter"`
	MaxValidUntil         time.Time         `json:"maxValidUntil"`
	ValidBefore           time.Time         `json:"validBefore"`
	Principals            []string          `json:"principals"`
	Extensions            map[string]string `json:"extensions,omitempty"`
	CriticalOptions       map[string]string `json:"criticalOptions,omitempty"`
	Certificate           string            `json:"certificate"`
	ConfigurationKey      string            `json:"configurationKey"`
	AuthorizationKind     string            `json:"authorizationKind,omitempty"`
	Audience              string            `json:"audience,omitempty"`
	EvidenceDigest        string            `json:"evidenceDigest"`
	ParentEvidenceDigest  string            `json:"parentEvidenceDigest,omitempty"`
}

func resolveSshCertificateSpec(conf *configuration.EnvironmentSshCertificate, req Context, settings *sshResolvedSettings) (*sshCertificateSpec, error) {
	validity, err := conf.Validity.Render(req)
	if err != nil {
		return nil, fmt.Errorf("cannot render SSH certificate validity: %w", err)
	}
	if validity <= 0 {
		return nil, fmt.Errorf("rendered SSH certificate validity has to be positive")
	}
	validAfterSkew, err := conf.ValidAfterSkew.Render(req)
	if err != nil {
		return nil, fmt.Errorf("cannot render SSH certificate valid-after skew: %w", err)
	}
	if validAfterSkew < 0 {
		return nil, fmt.Errorf("rendered SSH certificate valid-after skew cannot be negative")
	}
	audience, err := conf.Audience.Render(req)
	if err != nil {
		return nil, fmt.Errorf("cannot render SSH certificate audience: %w", err)
	}
	audience = strings.TrimSpace(audience)
	if !conf.Audience.IsZero() && audience == "" {
		return nil, fmt.Errorf("rendered SSH certificate audience is empty")
	}
	if strings.IndexByte(audience, 0) >= 0 {
		return nil, fmt.Errorf("rendered SSH certificate audience contains NUL")
	}
	principals, err := conf.Principals.Render(req)
	if err != nil {
		return nil, fmt.Errorf("cannot render SSH certificate principals: %w", err)
	}
	principals = append([]string(nil), principals...)
	for i, principal := range principals {
		principal = strings.TrimSpace(principal)
		if principal == "" {
			return nil, fmt.Errorf("rendered SSH certificate principal [%d] is empty", i)
		}
		if strings.IndexByte(principal, 0) >= 0 {
			return nil, fmt.Errorf("rendered SSH certificate principal [%d] contains NUL", i)
		}
		principals[i] = principal
	}
	if !slices.Contains(principals, settings.user) {
		principals = append(principals, settings.user)
	}
	slices.Sort(principals)
	principals = slices.Compact(principals)

	extensions, err := conf.Extensions.Render(req)
	if err != nil {
		return nil, fmt.Errorf("cannot render SSH certificate extensions: %w", err)
	}
	for _, name := range []string{"permit-pty", "permit-port-forwarding", "permit-agent-forwarding"} {
		if value, exists := extensions[name]; exists && value != "" {
			return nil, fmt.Errorf("rendered SSH certificate extension %q must have an empty value", name)
		}
	}
	policy := authorization.AuthorizedKeyPolicyOf(req.Authorization())
	if policy != nil && !policy.PtyAllowed {
		delete(extensions, "permit-pty")
	}
	if !settings.forwardAllowed || policy != nil && (!policy.PortForwardingAllowed || policy.HasPortForwardingDestinationRestrictions()) {
		delete(extensions, "permit-port-forwarding")
	}
	if !authorization.IsAgentForwardingAllowed(req.Authorization()) {
		delete(extensions, "permit-agent-forwarding")
	}
	parentEvidence := authorization.AuthorizationEvidenceOf(req.Authorization())
	parentDigest := ""
	var maxValidBefore time.Time
	if parentEvidence != nil {
		parentRaw, err := authorization.EncodeAuthorizationEvidence(parentEvidence)
		if err != nil {
			return nil, fmt.Errorf("cannot encode inherited authorization evidence: %w", err)
		}
		parentDigest = sshCertificateEvidenceDigest(parentRaw)
		if last := parentEvidence.LastHop(); last != nil {
			maxValidBefore = last.ValidBefore
		}
	}

	return &sshCertificateSpec{
		validity:          validity,
		validAfterSkew:    validAfterSkew,
		principals:        principals,
		extensions:        extensions,
		authorizationKind: authorization.KindOf(req.Authorization()),
		audience:          audience,
		parentEvidence:    parentEvidence,
		parentDigest:      parentDigest,
		maxValidBefore:    maxValidBefore,
	}, nil
}

func (this *SshRepository) ensureUserCertificate(ctx context.Context, req Request, sess session.Session, settings *sshResolvedSettings) (gossh.Signer, string, error) {
	unlock := this.sessionLocks.Lock(sess.Id())
	defer unlock()
	info, err := sess.Info(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("cannot load session state before SSH certificate issuance: %w", err)
	}
	if info != nil && info.State() == session.StateDisposed {
		return nil, "", fmt.Errorf("cannot issue or load an SSH certificate for disposed session %s", sess.Id())
	}

	raw, err := sess.EnvironmentToken(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("cannot load SSH certificate state: %w", err)
	}
	var state *sshUserCertificateState
	if len(raw) == 0 {
		state, err = this.issueUserCertificate(ctx, req, sess, settings)
		if err != nil {
			return nil, "", err
		}
		raw, err = json.Marshal(state)
		if err != nil {
			return nil, "", fmt.Errorf("cannot encode SSH certificate state: %w", err)
		}
		if err := sess.SetEnvironmentToken(ctx, raw); err != nil {
			return nil, "", fmt.Errorf("cannot persist SSH certificate state: %w", err)
		}
	} else {
		state, err = decodeSshUserCertificateState(raw)
		if err != nil {
			return nil, "", err
		}
	}

	cert, err := this.validateUserCertificateState(state, sess, settings, time.Now())
	if err != nil {
		return nil, "", err
	}
	signer, err := gossh.NewCertSigner(cert, this.certificateKeys.subject)
	if err != nil {
		return nil, "", fmt.Errorf("cannot combine SSH user certificate with subject key: %w", err)
	}
	return signer, state.Certificate, nil
}

func (this *SshRepository) issueUserCertificate(ctx context.Context, req Request, sess session.Session, settings *sshResolvedSettings) (*sshUserCertificateState, error) {
	spec := settings.certificate
	if spec == nil {
		return nil, fmt.Errorf("SSH certificate settings are absent")
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	maxValidUntil := issuedAt.Add(spec.validity)
	if !maxValidUntil.After(issuedAt) {
		return nil, fmt.Errorf("rendered SSH certificate validity exceeds the supported time range")
	}
	validAfter := issuedAt.Add(-spec.validAfterSkew)
	validBefore := maxValidUntil
	if parent := spec.parentEvidence.LastHop(); parent != nil {
		if parent.ValidAfter.After(validAfter) {
			validAfter = parent.ValidAfter.UTC().Truncate(time.Second)
		}
		if parent.ValidBefore.Before(validBefore) {
			validBefore = parent.ValidBefore.UTC().Truncate(time.Second)
		}
	}
	if !validBefore.After(issuedAt) {
		return nil, fmt.Errorf("inherited authorization evidence expires before a new SSH certificate can be issued")
	}
	if validAfter.Unix() < 0 || validBefore.Unix() < 0 {
		return nil, fmt.Errorf("SSH certificate validity is outside of the supported Unix time range")
	}

	serial, err := randomSshCertificateSerial()
	if err != nil {
		return nil, fmt.Errorf("cannot generate SSH certificate serial: %w", err)
	}
	keyId := "bifroest:" + this.flow.String() + ":" + sess.Id().String()
	extensions := make(map[string]string, len(spec.extensions)+1)
	for key, value := range spec.extensions {
		extensions[key] = value
	}
	authorizationKind := authorization.KindOf(req.Authorization())
	if authorizationKind == "" {
		return nil, fmt.Errorf("cannot issue SSH certificate without an authorization kind")
	}
	info, err := sess.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot load session information for SSH certificate: %w", err)
	}
	var evidence *authorization.AuthorizationEvidence
	if spec.parentEvidence != nil {
		evidence = spec.parentEvidence.Clone()
	} else {
		origin := req.Authorization().Remote()
		if info != nil {
			created, err := info.Created(ctx)
			if err != nil {
				return nil, fmt.Errorf("cannot load session creation information for SSH certificate: %w", err)
			}
			if created != nil && created.Remote() != nil {
				origin = created.Remote()
			}
		}
		if origin == nil {
			return nil, fmt.Errorf("cannot issue SSH certificate without session origin")
		}
		evidence = &authorization.AuthorizationEvidence{
			Schema: authorization.AuthorizationEvidenceSchema,
			Origin: authorization.AuthorizationEvidenceOrigin{
				User:              origin.User(),
				Host:              origin.Host().String(),
				AuthorizationKind: authorizationKind,
			},
		}
	}
	_, ptyAllowed := extensions["permit-pty"]
	_, portForwardingAllowed := extensions["permit-port-forwarding"]
	_, agentForwardingAllowed := extensions["permit-agent-forwarding"]
	if err := evidence.Append(authorization.AuthorizationEvidenceHop{
		CaFingerprint:          this.certificateKeys.authorityFingerprint,
		SubjectKeyFingerprint:  this.certificateKeys.subjectFingerprint,
		Serial:                 serial,
		KeyId:                  keyId,
		SessionId:              sess.Id().String(),
		Flow:                   sess.Flow().String(),
		AuthorizationKind:      authorizationKind,
		Audience:               spec.audience,
		TargetUser:             settings.user,
		IssuedAt:               issuedAt,
		ValidAfter:             validAfter,
		ValidBefore:            validBefore,
		PtyAllowed:             ptyAllowed,
		PortForwardingAllowed:  portForwardingAllowed,
		AgentForwardingAllowed: agentForwardingAllowed,
	}); err != nil {
		return nil, fmt.Errorf("cannot append SSH certificate authorization evidence: %w", err)
	}
	evidenceRaw, err := authorization.EncodeAuthorizationEvidence(evidence)
	if err != nil {
		return nil, fmt.Errorf("cannot encode SSH certificate evidence: %w", err)
	}
	extensions[authorization.AuthorizationEvidenceExtension] = string(evidenceRaw)
	criticalOptions := map[string]string{}
	if spec.audience != "" {
		criticalOptions[authorization.BifroestDelegationCriticalOption] = ""
	}

	cert := &gossh.Certificate{
		Nonce:           nil,
		Key:             this.certificateKeys.subject.PublicKey(),
		Serial:          serial,
		CertType:        gossh.UserCert,
		KeyId:           keyId,
		ValidPrincipals: append([]string(nil), spec.principals...),
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions: gossh.Permissions{
			CriticalOptions: criticalOptions,
			Extensions:      extensions,
		},
	}
	if err := cert.SignCert(crand.Reader, this.certificateKeys.authority); err != nil {
		return nil, fmt.Errorf("cannot sign SSH user certificate: %w", err)
	}

	return &sshUserCertificateState{
		Schema:                sshUserCertificateSchema,
		State:                 "ready",
		SessionId:             sess.Id().String(),
		Flow:                  sess.Flow().String(),
		TargetAddress:         settings.address.String(),
		TargetUser:            settings.user,
		SubjectKeyFingerprint: this.certificateKeys.subjectFingerprint,
		CaFingerprint:         this.certificateKeys.authorityFingerprint,
		Serial:                serial,
		KeyId:                 keyId,
		IssuedAt:              issuedAt,
		ValidAfter:            validAfter,
		MaxValidUntil:         maxValidUntil,
		ValidBefore:           validBefore,
		Principals:            append([]string(nil), spec.principals...),
		Extensions:            extensions,
		CriticalOptions:       criticalOptions,
		Certificate:           strings.TrimSpace(string(gossh.MarshalAuthorizedKey(cert))),
		ConfigurationKey:      this.certificateKeys.configurationKey,
		AuthorizationKind:     authorizationKind,
		Audience:              spec.audience,
		EvidenceDigest:        sshCertificateEvidenceDigest(evidenceRaw),
		ParentEvidenceDigest:  spec.parentDigest,
	}, nil
}

func decodeSshUserCertificateState(raw []byte) (*sshUserCertificateState, error) {
	var state sshUserCertificateState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("cannot decode SSH certificate state: %w", err)
	}
	if state.Schema != sshUserCertificateSchema || state.State != "ready" {
		return nil, fmt.Errorf("unsupported or incomplete SSH certificate state")
	}
	return &state, nil
}

func (this *SshRepository) validateUserCertificateState(state *sshUserCertificateState, sess session.Session, settings *sshResolvedSettings, now time.Time) (*gossh.Certificate, error) {
	fail := func(reason string) (*gossh.Certificate, error) {
		return nil, fmt.Errorf("stored SSH certificate is incompatible with session %s: %s", sess.Id(), reason)
	}
	if state.SessionId != sess.Id().String() || state.Flow != sess.Flow().String() {
		return fail("session identity changed")
	}
	if state.ConfigurationKey != this.certificateKeys.configurationKey {
		return fail("certificate configuration changed")
	}
	if settings.certificate == nil || state.AuthorizationKind != settings.certificate.authorizationKind {
		return fail("authorization kind changed")
	}
	if err := this.validateSubjectIdentityFile(); err != nil {
		return fail(err.Error())
	}
	if state.TargetAddress != settings.address.String() || state.TargetUser != settings.user {
		return fail("target changed")
	}
	if state.SubjectKeyFingerprint != this.certificateKeys.subjectFingerprint {
		return fail("subject key changed")
	}
	if !now.Before(state.ValidBefore) || state.ValidBefore.After(state.MaxValidUntil) {
		return fail("certificate expired or has an invalid validity boundary")
	}
	if state.EvidenceDigest == "" || state.Audience != settings.certificate.audience || state.ParentEvidenceDigest != settings.certificate.parentDigest {
		return fail("authorization evidence changed or is incomplete")
	}
	if !settings.certificate.maxValidBefore.IsZero() && state.ValidBefore.After(settings.certificate.maxValidBefore) {
		return fail("certificate exceeds inherited validity")
	}
	if settings.certificate == nil || !slices.Equal(state.Principals, settings.certificate.principals) {
		return fail("principals changed")
	}
	if !sshCertificateExtensionsEqual(state.Extensions, settings.certificate.extensions) {
		return fail("required extensions changed")
	}

	public, _, _, rest, err := gossh.ParseAuthorizedKey([]byte(state.Certificate))
	if err != nil || len(strings.TrimSpace(string(rest))) > 0 {
		return fail("certificate cannot be parsed")
	}
	cert, ok := public.(*gossh.Certificate)
	if !ok || cert.CertType != gossh.UserCert {
		return fail("credential is not an SSH user certificate")
	}
	if cert.Serial != state.Serial || cert.KeyId != state.KeyId ||
		gossh.FingerprintSHA256(cert.Key) != state.SubjectKeyFingerprint ||
		gossh.FingerprintSHA256(cert.SignatureKey) != state.CaFingerprint ||
		cert.ValidAfter != uint64(state.ValidAfter.Unix()) || cert.ValidBefore != uint64(state.ValidBefore.Unix()) ||
		!slices.Equal(cert.ValidPrincipals, state.Principals) {
		return fail("certificate does not match its persisted metadata")
	}
	if !maps.Equal(cert.CriticalOptions, state.CriticalOptions) || !maps.Equal(cert.Extensions, state.Extensions) {
		return fail("certificate permissions do not match their persisted metadata")
	}
	expectedCriticalOptions := map[string]string{}
	if state.Audience != "" {
		expectedCriticalOptions[authorization.BifroestDelegationCriticalOption] = ""
	}
	if !maps.Equal(state.CriticalOptions, expectedCriticalOptions) {
		return fail("certificate delegation marker does not match its audience")
	}
	evidenceRaw, exists := cert.Extensions[authorization.AuthorizationEvidenceExtension]
	if !exists || sshCertificateEvidenceDigest([]byte(evidenceRaw)) != state.EvidenceDigest {
		return fail("certificate evidence does not match its persisted digest")
	}
	evidence, err := authorization.DecodeAuthorizationEvidence([]byte(evidenceRaw))
	if err != nil {
		return fail(err.Error())
	}
	last := evidence.LastHop()
	expectedKeyId := "bifroest:" + sess.Flow().String() + ":" + sess.Id().String()
	if last == nil || last.SessionId != sess.Id().String() || last.Flow != sess.Flow().String() ||
		last.KeyId != expectedKeyId || last.AuthorizationKind != state.AuthorizationKind ||
		last.Audience != state.Audience || !last.IssuedAt.Equal(state.IssuedAt) {
		return fail("certificate evidence does not match its session metadata")
	}
	expectedParentDigest := ""
	if len(evidence.Hops) > 1 {
		parent := evidence.Clone()
		parent.Hops = parent.Hops[:len(parent.Hops)-1]
		parentRaw, err := authorization.EncodeAuthorizationEvidence(parent)
		if err != nil {
			return fail(err.Error())
		}
		expectedParentDigest = sshCertificateEvidenceDigest(parentRaw)
	}
	if state.ParentEvidenceDigest != expectedParentDigest {
		return fail("certificate evidence does not match its parent digest")
	}
	if _, err := authorization.ValidateAuthorizationEvidenceCertificate(evidence, cert, settings.user, now); err != nil {
		return fail(err.Error())
	}
	var supportedCriticalOptions []string
	if state.Audience != "" {
		supportedCriticalOptions = []string{authorization.BifroestDelegationCriticalOption}
	}
	checker := gossh.CertChecker{
		SupportedCriticalOptions: supportedCriticalOptions,
		IsUserAuthority: func(authority gossh.PublicKey) bool {
			return gossh.FingerprintSHA256(authority) == state.CaFingerprint
		},
		Clock: func() time.Time { return now },
	}
	if err := checker.CheckCert(settings.user, cert); err != nil {
		return fail(err.Error())
	}
	return cert, nil
}

func (this *SshRepository) validateSubjectIdentityFile() error {
	raw, err := os.ReadFile(this.certificateKeys.subjectIdentityFile)
	if err != nil {
		return fmt.Errorf("subject identity file is unavailable: %w", err)
	}
	signer, err := gossh.ParsePrivateKey(raw)
	if err != nil {
		return fmt.Errorf("subject identity file is invalid: %w", err)
	}
	if gossh.FingerprintSHA256(signer.PublicKey()) != this.certificateKeys.subjectFingerprint {
		return fmt.Errorf("subject identity key changed")
	}
	return nil
}

func randomSshCertificateSerial() (uint64, error) {
	for {
		var raw [8]byte
		if _, err := crand.Read(raw[:]); err != nil {
			return 0, err
		}
		if result := binary.BigEndian.Uint64(raw[:]); result != 0 {
			return result, nil
		}
	}
}

func (this *SshRepository) IsSessionCompatible(ctx context.Context, sess session.Session) (bool, error) {
	raw, err := sess.EnvironmentToken(ctx)
	if err != nil {
		return false, fmt.Errorf("cannot load SSH certificate state: %w", err)
	}
	if this.conf.Certificate == nil {
		return len(raw) == 0, nil
	}
	if len(raw) == 0 {
		return false, nil
	}
	state, err := decodeSshUserCertificateState(raw)
	if err != nil {
		this.logger().With("session", sess).WithError(err).Warn("stored SSH certificate state is incompatible")
		return false, nil
	}
	var address bnet.HostPort
	if err := address.Set(state.TargetAddress); err != nil {
		return false, nil
	}
	settings := &sshResolvedSettings{
		address: address,
		user:    state.TargetUser,
		certificate: &sshCertificateSpec{
			principals:        append([]string(nil), state.Principals...),
			extensions:        sshCertificateUserExtensions(state.Extensions),
			authorizationKind: state.AuthorizationKind,
			audience:          state.Audience,
			parentDigest:      state.ParentEvidenceDigest,
		},
	}
	_, err = this.validateUserCertificateState(state, sess, settings, time.Now())
	if err != nil {
		this.logger().With("session", sess).WithError(err).Debug("stored SSH certificate is not reusable")
		return false, nil
	}
	return true, nil
}

func (this *SshRepository) IsSessionCompatibleWith(ctx Context, sess session.Session) (bool, error) {
	if this.conf.Certificate == nil {
		return this.IsSessionCompatible(ctx.Context(), sess)
	}
	raw, err := sess.EnvironmentToken(ctx.Context())
	if err != nil {
		return false, fmt.Errorf("cannot load SSH certificate state: %w", err)
	}
	if len(raw) == 0 {
		return false, nil
	}
	state, err := decodeSshUserCertificateState(raw)
	if err != nil {
		return false, nil
	}
	settings, err := this.resolveSettings(ctx)
	if err != nil {
		return false, err
	}
	if _, err := this.validateUserCertificateState(state, sess, settings, time.Now()); err != nil {
		this.logger().With("session", sess).WithError(err).Debug("stored SSH certificate is not compatible with the current authorization")
		return false, nil
	}
	return true, nil
}

func (this *SshRepository) disposeUserCertificate(ctx context.Context, sess session.Session) (bool, error) {
	unlock := this.sessionLocks.Lock(sess.Id())
	defer unlock()
	raw, err := sess.EnvironmentToken(ctx)
	if err != nil {
		return false, fmt.Errorf("cannot load SSH certificate state before disposal: %w", err)
	}
	if len(raw) == 0 {
		return false, nil
	}
	if err := sess.SetEnvironmentToken(ctx, nil); err != nil {
		return false, fmt.Errorf("cannot remove SSH certificate state: %w", err)
	}
	return true, nil
}

func sshCertificateUserExtensions(extensions map[string]string) map[string]string {
	result := make(map[string]string, len(extensions))
	for key, value := range extensions {
		if _, reserved := sshUserCertificateMetadataExtensions[key]; !reserved {
			result[key] = value
		}
	}
	return result
}

func sshCertificateExtensionsEqual(stored, required map[string]string) bool {
	return maps.Equal(sshCertificateUserExtensions(stored), required)
}

func sshCertificateConfigurationKey(conf *configuration.EnvironmentSsh) string {
	address := conf.Address.String()
	if conf.Address.IsHardCoded() {
		if resolved, err := bfssh.ParseAddress(address); err == nil {
			address = resolved.String()
		}
	}
	values := []string{"address=" + address, "user=" + conf.User.String(), "audience=" + conf.Certificate.Audience.String()}
	for i, principal := range conf.Certificate.Principals {
		values = append(values, fmt.Sprintf("principal[%d]=%s", i, principal.String()))
	}
	keys := make([]string, 0, len(conf.Certificate.Extensions))
	for key := range conf.Certificate.Extensions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values = append(values, "extension="+key+"="+conf.Certificate.Extensions[key].String())
	}
	digest := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return "SHA256:" + hex.EncodeToString(digest[:])
}

func sshCertificateEvidenceDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "SHA256:" + hex.EncodeToString(digest[:])
}
