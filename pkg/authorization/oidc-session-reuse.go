package authorization

import (
	"context"
	"fmt"
	"time"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

// primarySessionReuse checks the existing session's own grant, not the freshly
// presented grant. This uses the same lock as reconnect, background refresh and
// pending-token promotion; a fresh login cannot clobber or reset that chain.
func (this *OidcDeviceAuthAuthorizer) primarySessionReuse(identity authentication.Identity, fresh *oidcToken) session.Predicate {
	return func(ctx context.Context, candidate session.Session) (bool, error) {
		unlock, err := this.lockSession(ctx, candidate)
		if err != nil {
			return false, err
		}
		defer unlock()
		token, err := this.readSessionToken(ctx, candidate)
		if errors.Is(err, ErrNoSuchAuthorization) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !oidcTokenHasIdentity(token, identity) {
			return false, fmt.Errorf("persisted OIDC credentials differ from the bound primary identity")
		}
		if this.conf != nil && this.conf.RefreshEnabled() {
			if this.conf.ForceDisposeSessionOn != "never" {
				// A provider/JWKS request made for the retained grant must not
				// outlive its own verification deadline because this login is fresh.
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, token.LastVerifiedAt.Add(this.maxUnverifiedFor()))
				defer cancel()
			}
			force := !token.Expiry.IsZero() && !time.Now().Before(token.Expiry)
			if this.conf.RetrieveIdToken && token.IdToken != "" {
				_, verifyErr := this.verifyToken(ctx, token)
				force = force || errors.IsType(verifyErr, errors.Expired)
			}
			_, lost, err := this.refreshSession(ctx, candidate, token, force)
			if lost {
				if this.OnLostAccess != nil {
					this.OnLostAccess(candidate)
				}
				return false, nil
			}
			if err != nil {
				return false, err
			}
			latest, err := this.readSessionToken(ctx, candidate)
			if errors.Is(err, ErrNoSuchAuthorization) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			if !oidcTokenHasIdentity(latest, identity) || latest.Pending != nil {
				return false, fmt.Errorf("OIDC session identity was not verified after refresh")
			}
			if !latest.Expiry.IsZero() && !time.Now().Before(latest.Expiry) {
				return false, fmt.Errorf("OIDC session grant is expired after refresh")
			}
		} else if token.Pending != nil {
			// A configuration change must not make previously pending credentials
			// usable by turning refresh/verification off.
			return false, fmt.Errorf("OIDC session has pending unverified credentials")
		} else {
			// With refresh AND disposal disabled there is no rotating chain or
			// background refresh owner. A regular verified login may replace that
			// non-refreshing snapshot under the same lock as key reconnects, but
			// out-of-order primary completions must not roll verification back.
			if !oidcTokenHasIdentity(fresh, identity) {
				return false, fmt.Errorf("fresh OIDC primary identity is unavailable")
			}
			if fresh.LastVerifiedAt.After(token.LastVerifiedAt) {
				if err := this.updateSessionWith(ctx, fresh, candidate); err != nil {
					return false, err
				}
			}
		}
		return true, ctx.Err()
	}
}

func oidcTokenHasIdentity(token *oidcToken, identity authentication.Identity) bool {
	return token != nil && identity.IsAuthenticated() && token.Issuer == identity.Issuer && token.Subject == identity.Subject && !token.LastVerifiedAt.IsZero()
}
