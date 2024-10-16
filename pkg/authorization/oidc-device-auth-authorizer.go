package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	log "github.com/echocat/slf4g"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

var (
	_ = RegisterAuthorizer(NewOidcDeviceAuth)
)

type OidcDeviceAuthAuthorizer struct {
	flow configuration.FlowName
	conf *configuration.AuthorizationOidcDeviceAuth

	Logger log.Logger

	oauth2Config oauth2.Config
	provider     *coidc.Provider
	verifier     *coidc.IDTokenVerifier
}

func NewOidcDeviceAuth(ctx context.Context, flow configuration.FlowName, conf *configuration.AuthorizationOidcDeviceAuth) (*OidcDeviceAuthAuthorizer, error) {
	fail := func(err error) (*OidcDeviceAuthAuthorizer, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*OidcDeviceAuthAuthorizer, error) {
		return fail(errors.Newf(errors.Config, msg, args...))
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if conf == nil {
		return failf("nil configuration")
	}

	rCtx := noopContext{}
	issuer, err := conf.Issuer.Render(rCtx)
	if err != nil {
		return failf("cannot render issuer: %w", err)
	}

	provider, err := coidc.NewProvider(ctx, issuer.String())
	if err != nil {
		return failf("cannot evaluate OIDC issuer %q: %w", issuer, err)
	}

	clientId, err := conf.ClientId.Render(rCtx)
	if err != nil {
		return failf("cannot render clientId: %w", err)
	}
	clientSecret, err := conf.ClientSecret.Render(rCtx)
	if err != nil {
		return failf("cannot render clientSecret: %w", err)
	}
	rawScopes, err := conf.Scopes.Render(rCtx)
	if err != nil {
		return failf("cannot render scopes: %w", err)
	}
	var scopes []string
	for _, rawScope := range rawScopes {
		rawScope = strings.TrimSpace(rawScope)
		if rawScope == "" {
			continue
		}
		scopes = append(scopes, rawScope)
	}

	result := OidcDeviceAuthAuthorizer{
		flow: flow,
		conf: conf,

		oauth2Config: oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		provider: provider,
		verifier: provider.Verifier(&coidc.Config{
			ClientID: clientId,
		}),
	}

	return &result, nil
}

type noopContext struct{}

func (this *OidcDeviceAuthAuthorizer) RestoreFromSession(ctx context.Context, sess session.Session, opts *RestoreOpts) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, errors.Newf(errors.System, "cannot restore authorization from session %v: %w", sess, err)
	}
	failf := func(t errors.Type, msg string, args ...any) (Authorization, error) {
		args = append([]any{sess}, args...)
		return nil, errors.Newf(t, "cannot restore authorization from session %v: "+msg, args...)
	}
	cleanFromSessionOnly := func() (Authorization, error) {
		if opts.IsAutoCleanUpAllowed() {
			// Clear the stored token.
			if err := sess.SetAuthorizationToken(ctx, nil); err != nil {
				return failf(errors.System, "cannot clear existing authorization token of session after oidc access token seems to be expired: %w", err)
			}
			opts.GetLogger(this.logger).
				With("session", sess).
				Info("session's oidc access token seems to be expired; therefore according authorization token was removed from session")
		}
		return nil, ErrNoSuchAuthorization
	}

	if !sess.Flow().IsEqualTo(this.flow) {
		return nil, ErrNoSuchAuthorization
	}

	tb, err := sess.AuthorizationToken(ctx)
	if err != nil {
		return failf(errors.System, "cannot retrieve token: %w", err)
	}

	if len(tb) == 0 {
		return nil, ErrNoSuchAuthorization
	}

	var t oidcToken
	if err := json.Unmarshal(tb, &t); err != nil {
		return failf(errors.System, "cannot decode token of: %w", err)
	}

	// TODO! Refresh the token
	auth, err := this.finalizeAuth(ctx, this.logger(), &t, !opts.IsAutoCleanUpAllowed())
	if errors.IsType(err, errors.Expired, errors.Permission) {
		return cleanFromSessionOnly()
	}
	if err != nil {
		return fail(err)
	}

	if err := this.updateSessionWith(ctx, &t, sess); err != nil {
		return fail(err)
	}
	auth.session = sess

	return auth, nil

}

func (this *OidcDeviceAuthAuthorizer) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize via oidc device auth: %w", err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	ctx := req.Context()

	dar, err := this.initiateDeviceAuth(ctx)
	if err != nil {
		return fail(err)
	}

	var verificationMessage string
	if v := dar.VerificationURIComplete; v != "" {
		verificationMessage = fmt.Sprintf("Open the following URL in your browser to login: %s", v)
	} else {
		verificationMessage = fmt.Sprintf("Open the following URL in your browser and provide the code %q to login: %s", dar.UserCode, dar.VerificationURI)
	}
	if err := req.SendInfo(verificationMessage); err != nil {
		return failf("cannot send device code request to user: %w", err)
	}

	buf, err := this.retrieveDeviceAuthToken(ctx, dar)
	if err != nil {
		return fail(err)
	}
	req.Logger().Debug("token received")

	t := newOidcToken(buf)
	auth, err := this.finalizeAuth(ctx, req.Logger(), &t, true)
	if err != nil {
		return fail(err)
	}
	auth.remote = req.Remote()

	if ok, err := req.Validate(auth); err != nil {
		return failf("error validating authorization: %w", err)
	} else if !ok {
		return Forbidden(req.Remote()), nil
	}

	sess, err := this.ensureSessionFor(req, &t)
	if err != nil {
		return fail(err)
	}

	auth.session = sess

	return auth, nil
}

func (this *OidcDeviceAuthAuthorizer) AuthorizePublicKey(req PublicKeyRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot restore oidc authorization with public key: %w", err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	sess, err := req.Sessions().FindByPublicKey(req.Context(), req.RemotePublicKey(), (&session.FindOpts{}).WithPredicate(
		session.IsFlow(this.flow),
		session.IsStillValid,
		session.IsRemoteName(req.Remote().User()),
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		return Forbidden(req.Remote()), nil
	}
	if err != nil {
		return failf("cannot find session: %w", err)
	}

	at, err := sess.AuthorizationToken(req.Context())
	if err != nil {
		return fail(err)
	}
	if len(at) == 0 {
		return Forbidden(req.Remote()), nil
	}

	var t oidcToken
	if err := json.Unmarshal(at, &t); err != nil {
		return fail(err)
	}
	// TODO! Refresh the token

	req.Logger().Debug("token restored")

	auth, err := this.finalizeAuth(req.Context(), req.Logger(), &t, true)
	if err != nil {
		return fail(err)
	}
	auth.sessionsPublicKey = req.RemotePublicKey()

	if ok, err := req.Validate(auth); err != nil {
		return fail(err)
	} else if !ok {
		return Forbidden(req.Remote()), nil
	}

	if err := this.updateSessionWith(req.Context(), &t, sess); err != nil {
		return fail(err)
	}

	auth.session = sess

	return auth, nil
}

func (this *OidcDeviceAuthAuthorizer) finalizeAuth(ctx context.Context, logger log.Logger, t *oidcToken, retrieveArtifactsAllowed bool) (*oidc, error) {
	fail := func(err error) (*oidc, error) {
		return nil, err
	}
	failf := func(message string, args ...any) (*oidc, error) {
		return fail(fmt.Errorf(message, args...))
	}

	auth := oidc{
		flow: this.flow,
	}

	if err := auth.token.SetRaw(t.Token); err != nil {
		return failf("cannot store token at response: %w", err)
	}

	if retrieveArtifactsAllowed && this.conf.RetrieveIdToken {
		idToken, err := this.verifyToken(ctx, t)
		if err != nil {
			return fail(err)
		}

		auth.idToken.IDToken = idToken

		logger.With("idToken", &auth.idToken).Debug("id token received")
	}

	if retrieveArtifactsAllowed && this.conf.RetrieveUserInfo {
		userInfo, err := this.getUserInfo(ctx, t)
		if err != nil {
			return fail(err)
		}

		auth.userInfo.UserInfo = userInfo

		logger.With("userInfo", &auth.userInfo).Debug("user info received")
	}

	return &auth, nil
}

func (this *OidcDeviceAuthAuthorizer) updateSessionWith(ctx context.Context, t *oidcToken, sess session.Session) error {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.Newf(errors.System, msg, args...))
	}

	tb, err := json.Marshal(t)
	if err != nil {
		return failf("cannot marshal authorization token: %w", err)
	}

	if err = sess.SetAuthorizationToken(ctx, tb); err != nil {
		return fail(err)
	}

	return nil
}

func (this *OidcDeviceAuthAuthorizer) ensureSessionFor(req Request, t *oidcToken) (session.Session, error) {
	fail := func(err error) (session.Session, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (session.Session, error) {
		return fail(errors.Newf(errors.System, msg, args...))
	}

	at, err := json.Marshal(t)
	if err != nil {
		return failf("cannot marshal authorization token: %w", err)
	}

	// TODO! Maybe find a way to restore an existing one?
	sess, err := req.Sessions().Create(req.Context(), this.flow, req.Remote(), at)
	if err != nil {
		return fail(err)
	}

	return sess, nil
}

func (this *OidcDeviceAuthAuthorizer) initiateDeviceAuth(ctx context.Context) (*oauth2.DeviceAuthResponse, error) {
	fail := func(err error) (*oauth2.DeviceAuthResponse, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*oauth2.DeviceAuthResponse, error) {
		return fail(errors.Newf(errors.Network, msg, args...))
	}

	if ctx == nil {
		ctx = context.Background()
	}

	response, err := this.oauth2Config.DeviceAuth(ctx)
	if err != nil {
		return failf("cannot initiate successful device auth: %w", err)
	}

	return response, err
}

func (this *OidcDeviceAuthAuthorizer) retrieveDeviceAuthToken(ctx context.Context, using *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	fail := func(err error) (*oauth2.Token, error) {
		return nil, err
	}
	failf := func(pt errors.Type, msg string, args ...any) (*oauth2.Token, error) {
		return fail(errors.Newf(pt, msg, args...))
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if using == nil || using.DeviceCode == "" {
		return failf(errors.System, "no device auth response provided")
	}

	response, err := this.oauth2Config.DeviceAccessToken(ctx, using, oauth2.SetAuthURLParam("client_secret", this.oauth2Config.ClientSecret))
	if errors.Is(err, context.DeadlineExceeded) {
		return failf(errors.User, "authorize of device timed out")
	}
	if errors.Is(err, context.Canceled) {
		return failf(errors.User, "authorize canceled by user")
	}
	var oaErr *oauth2.RetrieveError
	if errors.As(err, &oaErr) && oaErr.ErrorCode == "expired_token" {
		return failf(errors.User, "authorize of device timed out by IdP")
	}
	if err != nil {
		return failf(errors.Network, "cannot authorize device: %w", err)
	}

	return response, err
}

func (this *OidcDeviceAuthAuthorizer) verifyToken(ctx context.Context, token *oidcToken) (*coidc.IDToken, error) {
	fail := func(err error) (*coidc.IDToken, error) {
		return nil, err
	}
	failf := func(pt errors.Type, msg string, args ...any) (*coidc.IDToken, error) {
		return fail(errors.Newf(pt, msg, args...))
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if token.Token == nil || token.Token.AccessToken == "" {
		return failf(errors.System, "no token provided")
	}

	if token.IdToken == "" {
		return failf(errors.Permission, "token does not contain id_token")
	}

	idToken, err := this.verifier.Verify(ctx, token.IdToken)
	if errors.Is(err, (*coidc.TokenExpiredError)(nil)) {
		return failf(errors.Expired, "cannot verify ID token: %w", err)
	}
	if err != nil {
		return failf(errors.Permission, "cannot verify ID token: %w", err)
	}

	return idToken, nil
}

func (this *OidcDeviceAuthAuthorizer) getUserInfo(ctx context.Context, token *oidcToken) (*coidc.UserInfo, error) {
	fail := func(err error) (*coidc.UserInfo, error) {
		return nil, err
	}
	failf := func(pt errors.Type, msg string, args ...any) (*coidc.UserInfo, error) {
		return fail(errors.Newf(pt, msg, args...))
	}

	if ctx == nil {
		ctx = context.Background()
	}

	result, err := this.provider.UserInfo(ctx, oauth2.StaticTokenSource(token.Token))
	if err != nil {
		return failf(errors.Permission, "%w", err)
	}

	return result, nil
}

func (this *OidcDeviceAuthAuthorizer) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	return Forbidden(req.Remote()), nil
}

func (this *OidcDeviceAuthAuthorizer) Close() error {
	return nil
}

func (this *OidcDeviceAuthAuthorizer) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("authorizer")
}
