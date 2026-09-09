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
)

const sshUserCertificateSchema = "bifroest.ssh-user-certificate/v1"

const maxSshUserCertificateEvidenceSize = 4 * 1024

var sshUserCertificateMetadataExtensions = map[string]struct{}{
	"session-id@bifroest.engity.org":         {},
	"original-user@bifroest.engity.org":      {},
	"original-host@bifroest.engity.org":      {},
	"authorization-kind@bifroest.engity.org": {},
	"evidence-v1@bifroest.engity.org":        {},
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
	Certificate           string            `json:"certificate"`
	ConfigurationKey      string            `json:"configurationKey"`
	AuthorizationKind     string            `json:"authorizationKind,omitempty"`
}

type sshUserCertificateEvidence struct {
	Schema            string    `json:"schema"`
	SessionId         string    `json:"sessionId"`
	Flow              string    `json:"flow"`
	CreatedAt         time.Time `json:"createdAt,omitempty"`
	OriginalUser      string    `json:"originalUser,omitempty"`
	OriginalHost      string    `json:"originalHost,omitempty"`
	AuthorizationKind string    `json:"authorizationKind,omitempty"`
	TargetUser        string    `json:"targetUser"`
	Principals        []string  `json:"principals"`
	PtyAllowed        bool      `json:"ptyAllowed"`
	PortForwarding    bool      `json:"portForwardingAllowed"`
	AgentForwarding   bool      `json:"agentForwardingAllowed"`
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
	policy := authorization.AuthorizedKeyPolicyOf(req.Authorization())
	if policy != nil && !policy.PtyAllowed {
		delete(extensions, "permit-pty")
	}
	if !settings.forwardAllowed || policy != nil && !policy.PortForwardingAllowed {
		delete(extensions, "permit-port-forwarding")
	}
	if !authorization.IsAgentForwardingAllowed(req.Authorization()) {
		delete(extensions, "permit-agent-forwarding")
	}

	return &sshCertificateSpec{
		validity:          validity,
		validAfterSkew:    validAfterSkew,
		principals:        principals,
		extensions:        extensions,
		authorizationKind: authorization.KindOf(req.Authorization()),
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
	if validAfter.Unix() < 0 || maxValidUntil.Unix() < 0 {
		return nil, fmt.Errorf("SSH certificate validity is outside of the supported Unix time range")
	}

	serial, err := randomSshCertificateSerial()
	if err != nil {
		return nil, fmt.Errorf("cannot generate SSH certificate serial: %w", err)
	}
	keyId := "bifroest:" + this.flow.String() + ":" + sess.Id().String()
	extensions := make(map[string]string, len(spec.extensions)+len(sshUserCertificateMetadataExtensions))
	for key, value := range spec.extensions {
		extensions[key] = value
	}
	extensions["session-id@bifroest.engity.org"] = sess.Id().String()
	authorizationKind := authorization.KindOf(req.Authorization())
	if authorizationKind != "" {
		extensions["authorization-kind@bifroest.engity.org"] = authorizationKind
	}
	evidence := sshUserCertificateEvidence{
		Schema:            "bifroest.authorization-evidence/v1",
		SessionId:         sess.Id().String(),
		Flow:              sess.Flow().String(),
		AuthorizationKind: authorizationKind,
		TargetUser:        settings.user,
		Principals:        append([]string(nil), spec.principals...),
	}
	_, evidence.PtyAllowed = extensions["permit-pty"]
	_, evidence.PortForwarding = extensions["permit-port-forwarding"]
	_, evidence.AgentForwarding = extensions["permit-agent-forwarding"]
	info, err := sess.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot load session information for SSH certificate: %w", err)
	}
	if info != nil {
		created, err := info.Created(ctx)
		if err != nil {
			return nil, fmt.Errorf("cannot load session creation information for SSH certificate: %w", err)
		}
		if created != nil && created.Remote() != nil {
			evidence.CreatedAt = created.At()
			evidence.OriginalUser = created.Remote().User()
			evidence.OriginalHost = created.Remote().Host().String()
			extensions["original-user@bifroest.engity.org"] = created.Remote().User()
			extensions["original-host@bifroest.engity.org"] = created.Remote().Host().String()
		}
	}
	evidenceRaw, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("cannot encode SSH certificate evidence: %w", err)
	}
	if len(evidenceRaw) > maxSshUserCertificateEvidenceSize {
		return nil, fmt.Errorf("SSH certificate evidence exceeds %d bytes", maxSshUserCertificateEvidenceSize)
	}
	extensions["evidence-v1@bifroest.engity.org"] = string(evidenceRaw)

	cert := &gossh.Certificate{
		Nonce:           nil,
		Key:             this.certificateKeys.subject.PublicKey(),
		Serial:          serial,
		CertType:        gossh.UserCert,
		KeyId:           keyId,
		ValidPrincipals: append([]string(nil), spec.principals...),
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(maxValidUntil.Unix()),
		Permissions: gossh.Permissions{
			Extensions: extensions,
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
		ValidBefore:           maxValidUntil,
		Principals:            append([]string(nil), spec.principals...),
		Extensions:            extensions,
		Certificate:           strings.TrimSpace(string(gossh.MarshalAuthorizedKey(cert))),
		ConfigurationKey:      this.certificateKeys.configurationKey,
		AuthorizationKind:     authorizationKind,
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
	if !now.Before(state.MaxValidUntil) || !state.ValidBefore.Equal(state.MaxValidUntil) {
		return fail("certificate expired or has an invalid validity boundary")
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
	if len(cert.CriticalOptions) > 0 || !maps.Equal(cert.Extensions, state.Extensions) {
		return fail("certificate permissions do not match their persisted metadata")
	}
	checker := gossh.CertChecker{
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
	values := []string{"address=" + conf.Address.String(), "user=" + conf.User.String()}
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
