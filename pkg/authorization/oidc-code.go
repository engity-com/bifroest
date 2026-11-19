package authorization

import (
	"context"
	"fmt"
	"time"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/session"
)

var _ = RegisterAuthorizer(NewOidcAuthorizationCode)

// OidcBrowser is a trusted server capability, never selected by client JSON.
// It returns a freshly verified code-grant result to the ORIGINAL request.
type OidcBrowser interface {
	Login(InteractiveRequest, *OidcDeviceAuthAuthorizer) (*oauth2.Token, error)
}
type oidcBrowserContextKey struct{}

func WithOidcBrowser(ctx context.Context, browser OidcBrowser) context.Context {
	return context.WithValue(ctx, oidcBrowserContextKey{}, browser)
}

func NewOidcAuthorizationCode(ctx context.Context, flow configuration.FlowName, conf *configuration.AuthorizationOidcAuthorizationCode) (*OidcDeviceAuthAuthorizer, error) {
	if conf == nil {
		return nil, fmt.Errorf("OIDC code configuration is absent")
	}
	return newOidcAuthorizer(ctx, flow, &conf.AuthorizationOidcDeviceAuth, conf)
}

func (this *OidcDeviceAuthAuthorizer) authorizationKind() string {
	if this.code != nil {
		return "oidc-authorization-code"
	}
	return "oidc-device-auth"
}

func (this *OidcDeviceAuthAuthorizer) matchesTokenGrant(token *oidcToken) bool {
	if this.code != nil {
		return token.Grant == "authorization_code"
	}
	return token.Grant == ""
}

func (this *OidcDeviceAuthAuthorizer) CodeConfiguration() *configuration.AuthorizationOidcAuthorizationCode {
	return this.code
}
func (this *OidcDeviceAuthAuthorizer) CodeFlow() configuration.FlowName { return this.flow }

func (this *OidcDeviceAuthAuthorizer) CodeAuthorizationURL(state, nonce, verifier string) string {
	return this.oauth2Config.AuthCodeURL(state, coidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
}

func (this *OidcDeviceAuthAuthorizer) CodeIssuer() string { return this.issuer }

// ExchangeCode never returns provider diagnostics (which may contain the code
// or other credentials) to callers. It validates identity before publication.
type OidcCodeResult struct {
	Token    *oauth2.Token
	Identity authentication.Identity
}

func (this *OidcDeviceAuthAuthorizer) ExchangeCode(ctx context.Context, code, verifier, nonce string) (*OidcCodeResult, error) {
	if this.code == nil {
		return nil, fmt.Errorf("code grant unavailable")
	}
	ctx, err := withSameOriginRedirects(ctx, this.oauth2Config.Endpoint.TokenURL)
	if err != nil {
		return nil, fmt.Errorf("code exchange unavailable")
	}
	token, err := this.oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil || !token.Valid() {
		return nil, fmt.Errorf("code exchange failed")
	}
	t := newOidcToken(token)
	id, err := this.verifyToken(ctx, &t)
	if err != nil || id.Subject == "" || id.Nonce != nonce || ctx.Err() != nil {
		return nil, fmt.Errorf("code identity verification failed")
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(token.AccessToken) != nil {
		return nil, fmt.Errorf("code access-token verification failed")
	}
	return &OidcCodeResult{Token: token, Identity: authentication.Identity{Principal: id.Subject, Issuer: id.Issuer, Subject: id.Subject}}, nil
}

func (this *OidcDeviceAuthAuthorizer) matchesCodeOrigin(origin string) bool {
	return this.code != nil && origin != "" && origin == this.code.Origin()
}

// Carry the absolute login deadline through verification and session creation,
// not just the browser wait. Keep adapter capabilities explicitly forwarded.
type oidcCodeRequest struct {
	InteractiveRequest
	ctx       context.Context
	selection connection.Selection
}

func (this *oidcCodeRequest) Context() context.Context        { return this.ctx }
func (this *oidcCodeRequest) Selection() connection.Selection { return this.selection }

// Preserve the adapter's optional template context for custom SSH instructions.
// The wrapper's bounded authentication context remains authoritative for I/O.
func (this *oidcCodeRequest) GetField(name string) (any, bool, error) {
	if parent, ok := this.InteractiveRequest.(interface {
		GetField(string) (any, bool, error)
	}); ok {
		return parent.GetField(name)
	}
	return nil, false, fmt.Errorf("unknown field %q", name)
}
func (this *oidcCodeRequest) SetAuthorizationContext(auth Authorization) {
	setAuthorizationContext(this.InteractiveRequest, auth)
}
func (this *oidcCodeRequest) ResolveAuthenticatedSessionWithReuse(auth Authorization, token []byte, reuse session.Predicate) (session.Session, bool, error) {
	if err := this.ctx.Err(); err != nil {
		return nil, true, err
	}
	if resolver, ok := this.InteractiveRequest.(interface {
		ResolveAuthenticatedSessionWithReuseContext(context.Context, Authorization, []byte, session.Predicate) (session.Session, bool, error)
	}); ok {
		return resolver.ResolveAuthenticatedSessionWithReuseContext(this.ctx, auth, token, reuse)
	}
	return resolveAuthenticatedSessionWithReuse(this.InteractiveRequest, auth, token, reuse)
}
func (this *oidcCodeRequest) SendOidcInfo(ctx context.Context, message string) error {
	if bounded, ok := this.InteractiveRequest.(interface {
		SendOidcInfo(context.Context, string) error
	}); ok {
		return bounded.SendOidcInfo(ctx, message)
	}
	return this.SendInfo(message)
}
func (this *oidcCodeRequest) Validate(auth Authorization) (bool, error) {
	if err := this.ctx.Err(); err != nil {
		return false, err
	}
	accepted, err := this.InteractiveRequest.Validate(auth)
	if this.ctx.Err() != nil {
		return false, this.ctx.Err()
	}
	return accepted, err
}

func (this *OidcDeviceAuthAuthorizer) authorizeCode(req InteractiveRequest) (Authorization, error) {
	selection, err := connection.SelectionOf(req)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(this.code.LoginTimeout.Native())
	if bounded, ok := req.(interface{ AuthenticationDeadline() time.Time }); ok {
		if earlier := bounded.AuthenticationDeadline(); !earlier.IsZero() && earlier.Before(deadline) {
			deadline = earlier
		}
	}
	ctx, cancel := context.WithDeadline(req.Context(), deadline)
	defer cancel()
	bounded := &oidcCodeRequest{InteractiveRequest: req, ctx: ctx, selection: selection}
	token, err := this.browser.Login(bounded, this)
	if err != nil || ctx.Err() != nil {
		return nil, fmt.Errorf("OIDC browser authentication failed")
	}
	return this.finishPrimary(bounded, token)
}
