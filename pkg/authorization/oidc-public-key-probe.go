package authorization

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

// probePublicKey only checks whether this key has a live remembered session.
// Do not restore claims, fetch UserInfo/JWKS, exchange or promote refresh tokens,
// write credentials, or notify access loss on an unsigned key offer. A probe may
// succeed even if the later verified attempt cannot restore access: actual
// authorization and contextual environment checks happen after possession proof.
func (this *OidcDeviceAuthAuthorizer) probePublicKey(req PublicKeyRequest) (Authorization, error) {
	// A previous flow may have left its prospective identity on this request.
	// It must not be used for OIDC's as-yet unrestored environment templates.
	setAuthorizationContext(req, nil)
	hasCredentials := func(ctx context.Context, candidate session.Session) (bool, error) {
		raw, err := candidate.AuthorizationToken(ctx)
		if err != nil {
			return false, err
		}
		if len(raw) == 0 {
			return false, nil
		}
		var token oidcToken
		if err := json.Unmarshal(raw, &token); err != nil {
			return false, fmt.Errorf("cannot decode remembered OIDC credentials")
		}
		return token.Token != nil && token.AccessToken != "", nil
	}
	sess, err := req.Sessions().FindByPublicKey(req.Context(), req.RemotePublicKey(), (&session.FindOpts{}).WithPredicate(
		session.IsFlow(this.flow),
		session.IsStillValid,
		session.IsRemoteName(req.Connection().Remote().User()),
		hasCredentials,
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		return Forbidden(req.Connection().Remote()), nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot probe remembered OIDC session: %w", err)
	}
	// This response deliberately contains no restored identity or token claims.
	return &oidc{flow: this.flow, remote: req.Connection().Remote(), session: sess, sessionsPublicKey: req.RemotePublicKey()}, nil
}
