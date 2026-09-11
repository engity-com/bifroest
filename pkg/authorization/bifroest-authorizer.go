package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

var _ = RegisterAuthorizer(NewBifroest)

type BifroestAuthorizer struct {
	flow           configuration.FlowName
	conf           *configuration.AuthorizationBifroest
	trustedUserCAs []ssh.PublicKey
	audiences      []string
}

func NewBifroest(_ context.Context, flow configuration.FlowName, conf *configuration.AuthorizationBifroest) (*BifroestAuthorizer, error) {
	failf := func(msg string, args ...any) (*BifroestAuthorizer, error) {
		return nil, errors.Newf(errors.Config, msg, args...)
	}
	if conf == nil {
		return failf("nil configuration")
	}
	trustedUserCAs, err := loadTrustedUserCAs(&conf.UserCertificateAuthorityProperties)
	if err != nil {
		return failf("cannot load trusted user CAs: %w", err)
	}
	if len(trustedUserCAs) == 0 {
		return failf("at least one trusted user CA is required")
	}
	var audiences []string
	if conf.Audiences == nil {
		audiences = []string{flow.String()}
	} else {
		audiences = append([]string{}, conf.Audiences...)
	}
	return &BifroestAuthorizer{
		flow:           flow,
		conf:           conf,
		trustedUserCAs: trustedUserCAs,
		audiences:      audiences,
	}, nil
}

func (*BifroestAuthorizer) SupportsUserCertificates() {}

func (this *BifroestAuthorizer) AuthorizePublicKey(req PublicKeyRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize bifroest %q via SSH user certificate: %w", req.Connection().Remote().User(), err)
	}
	evidence, policy, accepted, err := evaluateBifroestUserCertificate(
		req.RemotePublicKey(), req.Connection().Remote().User(), this.trustedUserCAs, this.audiences,
		this.conf.MaxCertificateValidity.Native(), time.Now(),
	)
	if err != nil {
		req.Connection().Logger().
			WithError(err).
			Debug("presented Bifroest delegation certificate is invalid")
		return Forbidden(req.Connection().Remote()), nil
	}
	if !accepted {
		return Forbidden(req.Connection().Remote()), nil
	}
	auth := &BifroestAuthorization{
		remote:   req.Connection().Remote(),
		flow:     this.flow,
		evidence: evidence,
		policy:   policy,
	}
	accepted, err = req.Validate(auth)
	if err != nil {
		return fail(fmt.Errorf("cannot validate request: %w", err))
	}
	if !accepted {
		return Forbidden(req.Connection().Remote()), nil
	}
	if !isPublicKeyVerified(req) {
		return auth, nil
	}
	token, err := encodeBifroestAuthorizationToken(auth)
	if err != nil {
		return fail(err)
	}
	sess, err := req.Sessions().FindByAccessToken(req.Context(), token, (&session.FindOpts{}).WithPredicate(
		session.IsFlow(this.flow),
		session.IsStillValid,
		session.IsRemoteName(req.Connection().Remote().User()),
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		sess, err = req.Sessions().Create(req.Context(), this.flow, req.Connection().Remote(), token)
	}
	if err != nil {
		return fail(fmt.Errorf("cannot ensure session: %w", err))
	}
	auth.session = sess
	return auth, nil
}

func (this *BifroestAuthorizer) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	return Forbidden(req.Connection().Remote()), nil
}

func (this *BifroestAuthorizer) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	return Forbidden(req.Connection().Remote()), nil
}

func (this *BifroestAuthorizer) RestoreFromSession(ctx context.Context, sess session.Session, _ *RestoreOpts) (Authorization, error) {
	failf := func(msg string, args ...any) (Authorization, error) {
		args = append([]any{sess}, args...)
		return nil, errors.Newf(errors.System, "cannot restore authorization from session %v: "+msg, args...)
	}
	if !sess.Flow().IsEqualTo(this.flow) {
		return nil, ErrNoSuchAuthorization
	}
	raw, err := sess.AuthorizationToken(ctx)
	if err != nil {
		return failf("cannot retrieve token: %w", err)
	}
	if len(raw) == 0 {
		return nil, ErrNoSuchAuthorization
	}
	token, err := decodeBifroestAuthorizationToken(raw)
	if err != nil {
		return failf("cannot decode token: %w", err)
	}
	info, err := sess.Info(ctx)
	if err != nil {
		return failf("cannot retrieve session info: %w", err)
	}
	lastAccessed, err := info.LastAccessed(ctx)
	if err != nil {
		return failf("cannot retrieve session last access: %w", err)
	}
	last := token.Evidence.LastHop()
	now := time.Now()
	if last == nil || token.Evidence.Origin.AuthorizationKind == "none" || last.Audience == "" || !slices.Contains(this.audiences, last.Audience) ||
		now.Before(last.ValidAfter) || !now.Before(last.ValidBefore) || last.IssuedAt.After(now.Add(maxAuthorizationEvidenceClockSkew)) ||
		this.conf.MaxCertificateValidity.Native() <= 0 || last.ValidBefore.Sub(last.IssuedAt) > this.conf.MaxCertificateValidity.Native() {
		return failf("persisted delegation evidence is no longer valid")
	}
	if lastAccessed.Remote() == nil || last.TargetUser != lastAccessed.Remote().User() {
		return failf("persisted delegation target does not match the session remote")
	}
	policy := &AuthorizedKeyPolicy{
		PtyAllowed:             token.Policy.PtyAllowed,
		PortForwardingAllowed:  token.Policy.PortForwardingAllowed,
		AgentForwardingAllowed: token.Policy.AgentForwardingAllowed,
	}
	return &BifroestAuthorization{
		remote:   lastAccessed.Remote(),
		flow:     this.flow.Clone(),
		session:  sess,
		evidence: token.Evidence.Clone(),
		policy:   policy,
	}, nil
}

func (*BifroestAuthorizer) Close() error { return nil }

func encodeBifroestAuthorizationToken(auth *BifroestAuthorization) ([]byte, error) {
	if auth == nil || auth.evidence == nil || auth.policy == nil {
		return nil, fmt.Errorf("cannot encode incomplete Bifroest authorization")
	}
	token := bifroestAuthorizationToken{
		Schema:   bifroestAuthorizationTokenSchema,
		Evidence: *auth.evidence.Clone(),
		Policy: AuthorizationEvidencePolicy{
			PtyAllowed:             auth.policy.PtyAllowed,
			PortForwardingAllowed:  auth.policy.PortForwardingAllowed,
			AgentForwardingAllowed: auth.policy.AgentForwardingAllowed,
		},
	}
	raw, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("cannot encode Bifroest authorization token: %w", err)
	}
	return raw, nil
}

func decodeBifroestAuthorizationToken(raw []byte) (*bifroestAuthorizationToken, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var token bifroestAuthorizationToken
	if err := decoder.Decode(&token); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("authorization token contains trailing data")
	}
	if token.Schema != bifroestAuthorizationTokenSchema {
		return nil, fmt.Errorf("unsupported authorization token schema %q", token.Schema)
	}
	if err := token.Evidence.Validate(); err != nil {
		return nil, err
	}
	if token.Evidence.Policy() != token.Policy {
		return nil, fmt.Errorf("authorization token policy does not match evidence")
	}
	return &token, nil
}
