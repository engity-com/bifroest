package authorization

import (
	"context"
	"encoding/base64"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

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

	Logger       log.Logger
	OnVerified   func(session.Session, time.Time)
	OnLostAccess func(session.Session)

	oauth2Config oauth2.Config
	provider     *coidc.Provider
	verifier     *coidc.IDTokenVerifier
	refreshLocks [64]struct {
		once  sync.Once
		ready chan struct{}
	}
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
	if issuer == nil {
		return failf("issuer is empty")
	}
	if err := requireOidcHttpsEndpoint("issuer", issuer.String()); err != nil {
		return fail(err)
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
	endpoint := provider.Endpoint()
	var metadata struct {
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return failf("cannot evaluate OIDC provider metadata: %w", err)
	}
	endpoint.AuthStyle, err = oidcClientAuthStyle(metadata.TokenEndpointAuthMethodsSupported)
	if err != nil {
		return fail(err)
	}
	if err := requireOidcHttpsEndpoint("token endpoint", endpoint.TokenURL); err != nil {
		return fail(err)
	}
	if err := requireOidcHttpsEndpoint("device authorization endpoint", endpoint.DeviceAuthURL); err != nil {
		return fail(err)
	}

	result := OidcDeviceAuthAuthorizer{
		flow: flow,
		conf: conf,

		oauth2Config: oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Endpoint:     endpoint,
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

func oidcClientAuthStyle(supported []string) (oauth2.AuthStyle, error) {
	if len(supported) == 0 {
		return oauth2.AuthStyleInHeader, nil
	}
	postSupported := false
	for _, method := range supported {
		switch method {
		case "client_secret_basic":
			return oauth2.AuthStyleInHeader, nil
		case "client_secret_post":
			postSupported = true
		}
	}
	if postSupported {
		return oauth2.AuthStyleInParams, nil
	}
	return oauth2.AuthStyleAutoDetect, errors.Config.Newf("OIDC provider does not support client_secret authentication")
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (this roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return this(req)
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectiveOriginPort(left) == effectiveOriginPort(right)
}

func requireOidcHttpsEndpoint(name, raw string) error {
	endpoint, err := url.Parse(raw)
	if err != nil {
		return errors.Config.Newf("%s is invalid: %w", name, err)
	}
	if !strings.EqualFold(endpoint.Scheme, "https") || endpoint.Host == "" {
		return errors.Config.Newf("%s must be an absolute HTTPS URL", name)
	}
	return nil
}

func effectiveOriginPort(value *url.URL) string {
	if port := value.Port(); port != "" {
		if numeric, err := strconv.ParseUint(port, 10, 16); err == nil {
			return strconv.FormatUint(numeric, 10)
		}
		return port
	}
	switch strings.ToLower(value.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func withBasicClientAuthentication(ctx context.Context, endpoint, clientId, clientSecret string) (context.Context, error) {
	if err := requireOidcHttpsEndpoint("client authentication endpoint", endpoint); err != nil {
		return nil, err
	}
	target, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if client == nil {
		client = http.DefaultClient
	}
	copyOfClient := *client
	transport := copyOfClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	copyOfClient.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		copyOfRequest := req.Clone(req.Context())
		if sameOrigin(req.URL, target) {
			copyOfRequest.SetBasicAuth(url.QueryEscape(clientId), url.QueryEscape(clientSecret))
		}
		return transport.RoundTrip(copyOfRequest)
	})
	return context.WithValue(ctx, oauth2.HTTPClient, &copyOfClient), nil
}

func withSameOriginRedirects(ctx context.Context, endpoint string) (context.Context, error) {
	if err := requireOidcHttpsEndpoint("OAuth endpoint", endpoint); err != nil {
		return nil, err
	}
	target, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if client == nil {
		client = http.DefaultClient
	}
	copyOfClient := *client
	previousCheck := copyOfClient.CheckRedirect
	copyOfClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !sameOrigin(req.URL, target) {
			return http.ErrUseLastResponse
		}
		if previousCheck != nil {
			return previousCheck(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	return context.WithValue(ctx, oauth2.HTTPClient, &copyOfClient), nil
}

func (this *OidcDeviceAuthAuthorizer) lockSession(ctx context.Context, sess session.Session) (func(), error) {
	h := fnv.New32a()
	_, _ = h.Write([]byte(sess.String()))
	lock := &this.refreshLocks[h.Sum32()%uint32(len(this.refreshLocks))]
	lock.once.Do(func() {
		lock.ready = make(chan struct{}, 1)
		lock.ready <- struct{}{}
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-lock.ready:
		if err := ctx.Err(); err != nil {
			lock.ready <- struct{}{}
			return nil, err
		}
		return func() { lock.ready <- struct{}{} }, nil
	}
}

func (this *OidcDeviceAuthAuthorizer) refreshDue(t *oidcToken) time.Time {
	if t == nil || t.Token == nil || t.ReceivedAt.IsZero() {
		return time.Now()
	}
	fallback := this.conf.RefreshToken.FallbackEvery.Native()
	if fallback <= 0 {
		fallback = 15 * time.Minute
	}
	if t.Expiry.IsZero() || !t.Expiry.After(t.ReceivedAt) {
		if !t.Expiry.IsZero() && !time.Now().Before(t.Expiry) {
			return time.Now()
		}
		return t.ReceivedAt.Add(fallback)
	}
	percent := this.conf.RefreshToken.AtLifetimePercent
	if percent == 0 {
		percent = 70
	}
	return t.ReceivedAt.Add(time.Duration(int64(t.Expiry.Sub(t.ReceivedAt)) * int64(percent) / 100))
}

func (this *OidcDeviceAuthAuthorizer) verificationDue(t *oidcToken) time.Time {
	max := this.maxUnverifiedFor()
	advance := min(max/10, 5*time.Minute)
	return t.LastVerifiedAt.Add(max - advance)
}

func (this *OidcDeviceAuthAuthorizer) maxUnverifiedFor() time.Duration {
	max := this.conf.RefreshToken.MaxUnverifiedFor.Native()
	if max <= 0 {
		return 30 * time.Minute
	}
	return max
}

func (this *OidcDeviceAuthAuthorizer) NextRefreshAt(ctx context.Context, sess session.Session) (time.Time, error) {
	if this.conf == nil || !this.conf.RefreshEnabled() {
		return time.Time{}, nil
	}
	unlock, err := this.lockSession(ctx, sess)
	if err != nil {
		return time.Time{}, err
	}
	defer unlock()
	t, err := this.readSessionToken(ctx, sess)
	if err != nil {
		if this.conf.ForceDisposeSessionOn != "never" &&
			(goerrors.Is(err, ErrNoSuchAuthorization) || goerrors.Is(err, ErrUnusableAuthorizationToken)) {
			return time.Now(), nil
		}
		return time.Time{}, err
	}
	if this.conf.ForceDisposeSessionOn != "never" && (t.RefreshToken == "" || t.Subject == "" || t.Issuer == "" || t.LastVerifiedAt.IsZero()) {
		return time.Now(), nil
	}
	return this.nextRefreshAt(t), nil
}

func (this *OidcDeviceAuthAuthorizer) nextRefreshAt(t *oidcToken) time.Time {
	next := this.refreshDue(t)
	if this.conf.RetrieveIdToken && t.IdToken != "" {
		// Unverified JWT expiry is only an earlier scheduling hint, never identity evidence.
		parts := strings.Split(t.IdToken, ".")
		if len(parts) != 3 {
			return time.Now()
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return time.Now()
		}
		var claims struct {
			Expiry json.Number `json:"exp"`
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			return time.Now()
		}
		exp, err := claims.Expiry.Int64()
		if err != nil || exp <= time.Now().Unix() {
			return time.Now()
		}
		if idExpiry := time.Unix(exp, 0); idExpiry.Before(next) {
			next = idExpiry
		}
	}
	if this.conf.ForceDisposeSessionOn != "never" && !t.LastVerifiedAt.IsZero() {
		if due := this.verificationDue(t); due.Before(next) {
			next = due
		}
	}
	return next
}

// VerificationDeadline returns the persisted grant's absolute verification deadline without contacting the provider.
func (this *OidcDeviceAuthAuthorizer) VerificationDeadline(ctx context.Context, sess session.Session) (time.Time, error) {
	unlock, err := this.lockSession(ctx, sess)
	if err != nil {
		return time.Time{}, err
	}
	defer unlock()
	t, err := this.readSessionToken(ctx, sess)
	if err != nil {
		return time.Time{}, err
	}
	if this.conf == nil || this.conf.ForceDisposeSessionOn == "never" {
		return time.Time{}, nil
	}
	if t.LastVerifiedAt.IsZero() || t.Subject == "" || t.Issuer == "" {
		return time.Time{}, fmt.Errorf("%w: OIDC session identity is not verified", ErrUnusableAuthorizationToken)
	}
	return t.LastVerifiedAt.Add(this.maxUnverifiedFor()), nil
}

func (this *OidcDeviceAuthAuthorizer) readSessionToken(ctx context.Context, sess session.Session) (*oidcToken, error) {
	if !sess.Flow().IsEqualTo(this.flow) {
		return nil, ErrNoSuchAuthorization
	}
	raw, err := sess.AuthorizationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot read OIDC session token: %w", err)
	}
	if len(raw) == 0 {
		return nil, ErrNoSuchAuthorization
	}
	var t oidcToken
	if err := json.Unmarshal(raw, &t); err != nil || t.Token == nil || t.AccessToken == "" {
		return nil, fmt.Errorf("%w: invalid persisted OIDC session token", ErrUnusableAuthorizationToken)
	}
	return &t, nil
}

// RefreshSession serializes token exchange and persistence with reconnects for this authorizer.
func (this *OidcDeviceAuthAuthorizer) RefreshSession(ctx context.Context, sess session.Session) (next time.Time, lost bool, err error) {
	if this.conf == nil || !this.conf.RefreshEnabled() {
		return time.Time{}, false, nil
	}
	unlock, err := this.lockSession(ctx, sess)
	if err != nil {
		return time.Time{}, false, err
	}
	defer unlock()
	t, err := this.readSessionToken(ctx, sess)
	if err != nil {
		if goerrors.Is(err, ErrNoSuchAuthorization) && this.conf.ForceDisposeSessionOn != "never" {
			return time.Time{}, true, fmt.Errorf("OIDC session has no authorization token")
		}
		return time.Now().Add(time.Minute), this.conf.ForceDisposeSessionOn != "never" && goerrors.Is(err, ErrUnusableAuthorizationToken), err
	}
	force := false
	if this.conf.RetrieveIdToken && t.IdToken != "" {
		verifyCtx := ctx
		if this.conf.ForceDisposeSessionOn != "never" && !t.LastVerifiedAt.IsZero() {
			var cancel context.CancelFunc
			verifyCtx, cancel = context.WithDeadline(ctx, t.LastVerifiedAt.Add(this.maxUnverifiedFor()))
			defer cancel()
		}
		_, err := this.verifyToken(verifyCtx, t)
		force = errors.IsType(err, errors.Expired)
	}
	return this.refreshSession(ctx, sess, t, force)
}

// refreshSession requires the session lock. The caller must reload the token under that lock.
func (this *OidcDeviceAuthAuthorizer) refreshSession(ctx context.Context, sess session.Session, t *oidcToken, force bool) (time.Time, bool, error) {
	now := time.Now()
	due := this.refreshDue(t)
	lostAccess := this.conf.ForceDisposeSessionOn != "never"
	deadline := t.LastVerifiedAt.Add(this.maxUnverifiedFor())
	if lostAccess && (t.Subject == "" || t.Issuer == "" || t.LastVerifiedAt.IsZero()) {
		return time.Time{}, true, fmt.Errorf("OIDC session identity is no longer verified")
	}
	if lostAccess && t.RefreshToken == "" {
		return time.Time{}, true, fmt.Errorf("OIDC session has no refresh token")
	}
	if lostAccess && !now.Before(deadline) {
		return time.Time{}, true, fmt.Errorf("OIDC refresh verification deadline exceeded")
	}
	if lostAccess && !now.Before(this.verificationDue(t)) {
		force = true
	}
	if !force && !t.ReceivedAt.IsZero() && now.Before(due) && (t.Expiry.IsZero() || now.Before(t.Expiry)) && (!lostAccess || now.Before(deadline)) {
		return this.nextRefreshAt(t), false, nil
	}
	retry := now.Add(time.Minute)
	if lostAccess && deadline.Before(retry) && now.Before(deadline) {
		retry = deadline
	}
	if t.RefreshToken == "" {
		return retry, lostAccess, fmt.Errorf("OIDC session has no refresh token")
	}
	if lostAccess {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	ctx, err := withSameOriginRedirects(ctx, this.oauth2Config.Endpoint.TokenURL)
	if err != nil {
		return retry, false, fmt.Errorf("cannot prepare OIDC refresh: %w", err)
	}
	// TokenSource returns its input without an exchange while the access token is valid.
	input := *t.Token
	input.Expiry = now.Add(-time.Second)
	updated, err := this.oauth2Config.TokenSource(ctx, &input).Token()
	if err != nil {
		var retrieveErr *oauth2.RetrieveError
		if goerrors.As(err, &retrieveErr) && retrieveErr.ErrorCode == "invalid_grant" {
			return retry, lostAccess, fmt.Errorf("OIDC refresh token was rejected")
		}
		if lostAccess && !time.Now().Before(deadline) {
			return time.Time{}, true, fmt.Errorf("OIDC refresh could not verify identity before deadline")
		}
		return retry, false, fmt.Errorf("OIDC token refresh failed")
	}
	if lostAccess && !time.Now().Before(deadline) {
		return time.Time{}, true, fmt.Errorf("OIDC refresh verification deadline exceeded")
	}
	fresh := newOidcToken(updated)
	if !fresh.Expiry.IsZero() && !time.Now().Before(fresh.Expiry) {
		return retry, lostAccess && !time.Now().Before(deadline), fmt.Errorf("OIDC refresh returned an expired access token")
	}
	fresh.Subject, fresh.Issuer, fresh.LastVerifiedAt = t.Subject, t.Issuer, t.LastVerifiedAt
	if fresh.IdToken != "" {
		verified, verifyErr := this.verifyToken(ctx, &fresh)
		if verifyErr != nil {
			if lostAccess && !time.Now().Before(deadline) {
				return time.Time{}, true, fmt.Errorf("OIDC refreshed identity could not be verified before deadline")
			}
			return retry, false, fmt.Errorf("OIDC refreshed ID token could not be verified")
		}
		if t.Subject != "" && (t.Subject != verified.Subject || t.Issuer != verified.Issuer) {
			return retry, lostAccess, fmt.Errorf("OIDC refreshed identity differs from session identity")
		}
		fresh.Subject, fresh.Issuer, fresh.LastVerifiedAt = verified.Subject, verified.Issuer, time.Now()
	} else {
		if t.IdToken != "" && t.Subject != "" && t.Issuer != "" {
			if previous, err := this.verifyToken(ctx, t); err == nil && time.Now().Before(previous.Expiry) &&
				previous.Subject == t.Subject && previous.Issuer == t.Issuer {
				fresh.IdToken = t.IdToken
			}
		}
		fresh.LastVerifiedAt = time.Now()
	}
	if lostAccess && !time.Now().Before(deadline) {
		return time.Time{}, true, fmt.Errorf("OIDC refresh verification deadline exceeded")
	}
	if err := this.updateSessionWith(ctx, &fresh, sess); err != nil {
		return retry, lostAccess, fmt.Errorf("cannot persist refreshed OIDC token: %w", err)
	}
	if lostAccess && this.OnVerified != nil {
		this.OnVerified(sess, fresh.LastVerifiedAt.Add(this.maxUnverifiedFor()))
	}
	return this.nextRefreshAt(&fresh), false, nil
}

func (this *OidcDeviceAuthAuthorizer) RestoreFromSession(ctx context.Context, sess session.Session, opts *RestoreOpts) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, errors.Newf(errors.System, "cannot restore authorization from session %v: %w", sess, err)
	}
	failf := func(t errors.Type, msg string, args ...any) (Authorization, error) {
		args = append([]any{sess}, args...)
		return nil, errors.Newf(t, "cannot restore authorization from session %v: "+msg, args...)
	}
	if !sess.Flow().IsEqualTo(this.flow) {
		return nil, ErrNoSuchAuthorization
	}
	unlock, err := this.lockSession(ctx, sess)
	if err != nil {
		return nil, err
	}
	defer unlock()

	tb, err := sess.AuthorizationToken(ctx)
	if err != nil {
		return failf(errors.System, "cannot retrieve token: %w", err)
	}

	if len(tb) == 0 {
		return nil, ErrNoSuchAuthorization
	}

	var t oidcToken
	if err := json.Unmarshal(tb, &t); err != nil {
		return nil, unusableAuthorizationToken(ctx, sess, opts, fmt.Errorf("cannot decode OIDC authorization token: %w", err))
	}
	if t.Token == nil || t.AccessToken == "" {
		return nil, unusableAuthorizationToken(ctx, sess, opts, fmt.Errorf("OIDC authorization token has no access token"))
	}
	refreshEnabled := this.conf != nil && this.conf.RefreshEnabled()
	if this.conf != nil && this.conf.RetrieveIdToken && t.IdToken == "" && !(refreshEnabled && !t.LastVerifiedAt.IsZero() && t.Subject != "" && t.Issuer != "") {
		return nil, unusableAuthorizationToken(ctx, sess, opts, fmt.Errorf("OIDC authorization token has no required ID token"))
	}
	if refreshEnabled && this.conf.ForceDisposeSessionOn != "never" && (t.Expiry.IsZero() || time.Now().Before(t.Expiry)) {
		if _, lost, err := this.refreshSession(ctx, sess, &t, false); lost {
			return nil, unusableAuthorizationToken(ctx, sess, opts, err)
		} else if err != nil {
			return fail(err)
		}
		updated, err := this.readSessionToken(ctx, sess)
		if err != nil {
			return fail(err)
		}
		t = *updated
	}
	if !t.Expiry.IsZero() && !time.Now().Before(t.Expiry) {
		if !refreshEnabled {
			return nil, unusableAuthorizationToken(ctx, sess, opts, fmt.Errorf("OIDC authorization token expired at %s", t.Expiry))
		}
		if _, lost, err := this.refreshSession(ctx, sess, &t, true); lost {
			return nil, unusableAuthorizationToken(ctx, sess, opts, err)
		} else if err != nil {
			return fail(err)
		}
		updated, err := this.readSessionToken(ctx, sess)
		if err != nil {
			return fail(err)
		}
		t = *updated
		if !t.Expiry.IsZero() && !time.Now().Before(t.Expiry) {
			return nil, unusableAuthorizationToken(ctx, sess, opts, fmt.Errorf("OIDC access token is expired"))
		}
	}
	if refreshEnabled && this.conf.RetrieveIdToken && t.IdToken != "" {
		if _, err := this.verifyToken(ctx, &t); errors.IsType(err, errors.Expired) {
			if _, lost, err := this.refreshSession(ctx, sess, &t, true); lost {
				return nil, unusableAuthorizationToken(ctx, sess, opts, err)
			} else if err != nil {
				return fail(err)
			}
			updated, err := this.readSessionToken(ctx, sess)
			if err != nil {
				return fail(err)
			}
			t = *updated
		}
	}
	if !t.Expiry.IsZero() && !time.Now().Before(t.Expiry) {
		return fail(fmt.Errorf("OIDC access token is expired"))
	}

	auth, err := this.finalizeAuth(ctx, this.logger(), &t, true)
	if errors.IsType(err, errors.Expired) {
		return nil, unusableAuthorizationToken(ctx, sess, opts, err)
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
	req.Connection().Logger().Debug("token received")

	t := newOidcToken(buf)
	if this.conf.RefreshEnabled() && t.RefreshToken == "" {
		return failf("OIDC provider did not issue a refresh token required for configured refresh")
	}
	auth, err := this.finalizeAuth(ctx, req.Connection().Logger(), &t, true)
	if err != nil {
		return fail(err)
	}
	if this.conf.ForceDisposeSessionOn != "never" || (this.conf.RefreshEnabled() && t.IdToken != "") {
		verified := auth.idToken.IDToken
		if verified == nil {
			verified, err = this.verifyToken(ctx, &t)
			if err != nil {
				return fail(err)
			}
		}
		t.Subject, t.Issuer, t.LastVerifiedAt = verified.Subject, verified.Issuer, time.Now()
		if t.Subject == "" || t.Issuer == "" {
			return failf("OIDC ID token has no subject or issuer")
		}
	}
	auth.remote = req.Connection().Remote()

	if ok, err := req.Validate(auth); err != nil {
		return failf("error validating authorization: %w", err)
	} else if !ok {
		return Forbidden(req.Connection().Remote()), nil
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

	var selectedAuth *oidc
	var selectedToken *oidcToken
	restoreCandidate := func(ctx context.Context, candidate session.Session) (bool, error) {
		unlock, err := this.lockSession(ctx, candidate)
		if err != nil {
			return false, err
		}
		defer unlock()
		at, err := candidate.AuthorizationToken(ctx)
		if err != nil {
			return false, err
		}
		if len(at) == 0 {
			return false, nil
		}
		var token oidcToken
		if err := json.Unmarshal(at, &token); err != nil {
			return false, err
		}
		if token.Token == nil || token.AccessToken == "" {
			return false, nil
		}
		if this.conf != nil && this.conf.ForceDisposeSessionOn != "never" && (token.Expiry.IsZero() || time.Now().Before(token.Expiry)) {
			if _, lost, err := this.refreshSession(ctx, candidate, &token, false); lost {
				if this.OnLostAccess != nil {
					this.OnLostAccess(candidate)
				}
				return false, nil
			} else if err != nil {
				return false, err
			}
			updated, err := this.readSessionToken(ctx, candidate)
			if err != nil {
				return false, err
			}
			token = *updated
		}
		if !token.Expiry.IsZero() && !time.Now().Before(token.Expiry) {
			if this.conf == nil || !this.conf.RefreshEnabled() {
				return false, nil
			}
			if _, lost, err := this.refreshSession(ctx, candidate, &token, true); lost {
				if this.OnLostAccess != nil {
					this.OnLostAccess(candidate)
				}
				return false, nil
			} else if err != nil {
				return false, err
			}
			updated, err := this.readSessionToken(ctx, candidate)
			if err != nil {
				return false, err
			}
			token = *updated
			if !token.Expiry.IsZero() && !time.Now().Before(token.Expiry) {
				return false, nil
			}
		}
		if this.conf != nil && this.conf.RefreshEnabled() && this.conf.RetrieveIdToken && token.IdToken != "" {
			if _, err := this.verifyToken(ctx, &token); errors.IsType(err, errors.Expired) {
				if _, lost, err := this.refreshSession(ctx, candidate, &token, true); lost {
					if this.OnLostAccess != nil {
						this.OnLostAccess(candidate)
					}
					return false, nil
				} else if err != nil {
					return false, err
				}
				updated, err := this.readSessionToken(ctx, candidate)
				if err != nil {
					return false, err
				}
				token = *updated
			}
		}
		if !token.Expiry.IsZero() && !time.Now().Before(token.Expiry) {
			return false, nil
		}
		auth, err := this.finalizeAuth(ctx, req.Connection().Logger(), &token, true)
		if errors.IsType(err, errors.Expired) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		auth.session = candidate
		auth.sessionsPublicKey = req.RemotePublicKey()
		accepted, err := req.Validate(auth)
		if err != nil || !accepted {
			return accepted, err
		}
		if err := this.updateSessionWith(ctx, &token, candidate); err != nil {
			return false, err
		}
		selectedAuth = auth
		selectedToken = &token
		return true, nil
	}
	sess, err := req.Sessions().FindByPublicKey(req.Context(), req.RemotePublicKey(), (&session.FindOpts{}).WithPredicate(
		session.IsFlow(this.flow),
		session.IsStillValid,
		session.IsRemoteName(req.Connection().Remote().User()),
		restoreCandidate,
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		return Forbidden(req.Connection().Remote()), nil
	}
	if err != nil {
		return failf("cannot find session: %w", err)
	}

	req.Connection().Logger().Debug("token restored")
	if selectedAuth == nil || selectedToken == nil || selectedAuth.session != sess {
		return failf("selected session was not restored")
	}
	return selectedAuth, nil
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

	if retrieveArtifactsAllowed && this.conf.RetrieveIdToken && t.IdToken != "" {
		idToken, err := this.verifyToken(ctx, t)
		if err != nil {
			return fail(err)
		} else {
			if t.Subject != "" && (idToken.Subject != t.Subject || idToken.Issuer != t.Issuer) {
				return failf("OIDC ID token identity differs from session identity")
			}
			auth.idToken.IDToken = idToken
			logger.With("idToken", &auth.idToken).Debug("id token received")
		}
	} else if retrieveArtifactsAllowed && this.conf.RetrieveIdToken && !this.conf.RefreshEnabled() {
		return failf("token does not contain id_token")
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
	sess, err := req.Sessions().Create(req.Context(), this.flow, req.Connection().Remote(), at)
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

	var (
		options []oauth2.AuthCodeOption
		err     error
	)
	ctx, err = withSameOriginRedirects(ctx, this.oauth2Config.Endpoint.DeviceAuthURL)
	if err != nil {
		return failf("cannot prepare device authorization redirect policy: %w", err)
	}
	if this.oauth2Config.Endpoint.AuthStyle == oauth2.AuthStyleInParams {
		options = append(options, oauth2.SetAuthURLParam("client_secret", this.oauth2Config.ClientSecret))
	} else {
		ctx, err = withBasicClientAuthentication(ctx, this.oauth2Config.Endpoint.DeviceAuthURL, this.oauth2Config.ClientID, this.oauth2Config.ClientSecret)
		if err != nil {
			return failf("cannot prepare device client authentication: %w", err)
		}
	}
	response, err := this.oauth2Config.DeviceAuth(ctx, options...)
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

	ctx, err := withSameOriginRedirects(ctx, this.oauth2Config.Endpoint.TokenURL)
	if err != nil {
		return failf(errors.Network, "cannot prepare token endpoint redirect policy: %w", err)
	}
	response, err := this.oauth2Config.DeviceAccessToken(ctx, using)
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
	var expired *coidc.TokenExpiredError
	if goerrors.As(err, &expired) {
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
	return Forbidden(req.Connection().Remote()), nil
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
