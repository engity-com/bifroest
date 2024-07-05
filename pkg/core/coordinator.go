package core

import (
	"context"
	"fmt"

	oidc2 "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/engity/pam-oidc/pkg/common"
	"github.com/engity/pam-oidc/pkg/errors"
	"github.com/engity/pam-oidc/pkg/oidc"
	"github.com/engity/pam-oidc/pkg/user"
)

func NewCoordinator(conf *Configuration) (*Coordinator, error) {
	return &Coordinator{
		Configuration: conf,
		UserEnsurer:   user.DefaultEnsurer,
	}, nil
}

type Coordinator struct {
	Configuration *Configuration
	UserEnsurer   user.Ensurer

	OnDeviceAuthStarted func(*oauth2.DeviceAuthResponse) error
	OnTokenReceived     func(token *oauth2.Token) error
	OnIdTokenReceived   func(token *oidc2.IDToken) error
	OnUserInfoReceived  func(token *oidc2.UserInfo) error
}

func (this *Coordinator) Run(ctx context.Context, requestedUserName string) (*user.User, CoordinatorRunResult, error) {
	fail := func(result CoordinatorRunResult, err error) (*user.User, CoordinatorRunResult, error) {
		return nil, result, err
	}

	if ctx == nil {
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = this.Configuration.ToContext()
		defer cancelFunc()
	}

	if v := this.Configuration.User.AllowedRequestingName; !v.IsZero() && !v.MatchString(requestedUserName) {
		return nil, CoordinatorRunResultRequestingNameForbidden, nil
	}
	if v := this.Configuration.User.ForbiddenRequestingName; !v.IsZero() && v.MatchString(requestedUserName) {
		return nil, CoordinatorRunResultRequestingNameForbidden, nil
	}

	rcOidcResolved, err := this.remoteAuthorize(ctx)
	if err != nil {
		return fail(CoordinatorRunResultOidcAuthorizeFailed, err)
	}

	rcReqResolved, err := this.toUserRequirement(rcOidcResolved)
	if err != nil {
		return fail(CoordinatorRunResultRequirementResolutionFailed, err)
	}

	if allowed, err := this.isLoginAllowed(rcReqResolved); err != nil {
		return fail(CoordinatorRunResultLoginAllowedResolutionFailed, err)
	} else if !allowed {
		return nil, CoordinatorRunResultLoginForbidden, nil
	}

	u, err := this.ensureUser(rcReqResolved)
	if err != nil {
		return fail(CoordinatorRunResultUserEnsuringFailed, err)
	}

	if u == nil {
		return nil, CoordinatorRunResultNoSuchUser, nil
	}

	return u, CoordinatorRunResultSuccess, nil
}

func (this *Coordinator) remoteAuthorize(ctx context.Context) (*RenderContextOidcResolved, error) {
	fail := func(err error) (*RenderContextOidcResolved, error) {
		return nil, err
	}
	failf := func(message string, args ...any) (*RenderContextOidcResolved, error) {
		return fail(errors.Newf(errors.TypeConfig, message, args...))
	}

	client, err := oidc.NewClient(ctx, this.Configuration)
	if err != nil {
		return fail(err)
	}

	dar, err := client.InitiateDeviceAuth(ctx)
	if err != nil {
		return fail(err)
	}

	if cb := this.OnDeviceAuthStarted; cb != nil {
		if err := cb(dar); err != nil {
			return fail(err)
		}
	}

	var result RenderContextOidcResolved

	token, err := client.RetrieveDeviceAuthToken(ctx, dar)
	if err != nil {
		return fail(err)
	}
	if cb := this.OnTokenReceived; cb != nil {
		if err := cb(token); err != nil {
			return fail(err)
		}
	}
	if err := result.Oidc.Token.SetRaw(token); err != nil {
		return failf("cannot set token to render context: %w", err)
	}

	if this.Configuration.Oidc.RetrieveIdToken {
		idToken, err := client.VerifyToken(ctx, token)
		if err != nil {
			return fail(err)
		}
		if cb := this.OnIdTokenReceived; cb != nil {
			if err := cb(idToken); err != nil {
				return fail(err)
			}
		}
		if err := result.Oidc.IdToken.SetRaw(idToken); err != nil {
			return failf("cannot set id token to render context: %w", err)
		}
	}

	if this.Configuration.Oidc.RetrieveUserInfo {
		userInfo, err := client.GetUserInfo(ctx, token)
		if err != nil {
			return fail(err)
		}
		if cb := this.OnUserInfoReceived; cb != nil {
			if err := cb(userInfo); err != nil {
				return fail(err)
			}
		}
		if err := result.Oidc.UserInfo.SetRaw(userInfo); err != nil {
			return failf("cannot set user info to render context: %w", err)
		}
	}

	return &result, nil
}

func (this *Coordinator) toUserRequirement(rc *RenderContextOidcResolved) (*RenderContextRequirementResolved, error) {
	fail := func(err error) (*RenderContextRequirementResolved, error) {
		return nil, err
	}
	failf := func(message string, args ...any) (*RenderContextRequirementResolved, error) {
		return fail(errors.Newf(errors.TypeConfig, message, args...))
	}

	req, err := this.Configuration.User.Render(common.StructuredKeyOf("user"), rc)
	if err != nil {
		return failf("cannot render user requirement based oidc information: %w", err)
	}

	return &RenderContextRequirementResolved{
		rc,
		req,
	}, nil
}

func (this *Coordinator) isLoginAllowed(rc *RenderContextRequirementResolved) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, err
	}
	failf := func(message string, args ...any) (bool, error) {
		return fail(errors.Newf(errors.TypeConfig, message, args...))
	}

	allowed, err := this.Configuration.User.LoginAllowed.Render(rc)
	if err != nil {
		return failf("cannot evaluate if user is allowed to longin or not: %w", err)
	}

	return allowed, nil
}

func (this *Coordinator) ensureUser(rc *RenderContextRequirementResolved) (*user.User, error) {
	fail := func(err error) (*user.User, error) {
		return nil, err
	}
	failf := func(pt errors.Type, message string, args ...any) (*user.User, error) {
		return fail(errors.Newf(pt, message, args...))
	}

	var opts user.EnsureOpts
	if v, err := this.Configuration.User.CreateIfAbsent.Render(rc); err != nil {
		return failf(errors.TypeConfig, "cannot resolve user.createIfAbsent: %w", err)
	} else {
		opts.CreateAllowed = &v
	}
	if v, err := this.Configuration.User.UpdateIfDifferent.Render(rc); err != nil {
		return failf(errors.TypeConfig, "cannot resolve user.updateIfDifferent: %w", err)
	} else {
		opts.ModifyAllowed = &v
	}

	u, err := this.UserEnsurer.Ensure(&rc.User, &opts)
	if err != nil {
		return failf(errors.TypeSystem, "cannot ensure user %v: %w", rc, u)
	}

	return u, nil
}

type CoordinatorRunResult uint8

const (
	CoordinatorRunResultSuccess CoordinatorRunResult = iota
	CoordinatorRunResultRequestingNameForbidden
	CoordinatorRunResultOidcAuthorizeFailed
	CoordinatorRunResultRequirementResolutionFailed
	CoordinatorRunResultLoginAllowedResolutionFailed
	CoordinatorRunResultLoginForbidden
	CoordinatorRunResultUserEnsuringFailed
	CoordinatorRunResultNoSuchUser
)

func (this CoordinatorRunResult) String() string {
	switch this {
	case CoordinatorRunResultSuccess:
		return "success"
	case CoordinatorRunResultRequestingNameForbidden:
		return "requesting name forbidden"
	case CoordinatorRunResultOidcAuthorizeFailed:
		return "oidc authorize failed"
	case CoordinatorRunResultRequirementResolutionFailed:
		return "requirement resolution failed"
	case CoordinatorRunResultLoginAllowedResolutionFailed:
		return "login allowed resolution failed"
	case CoordinatorRunResultLoginForbidden:
		return "login forbidden"
	case CoordinatorRunResultUserEnsuringFailed:
		return "user ensuring failed"
	case CoordinatorRunResultNoSuchUser:
		return "no such user"
	default:
		return fmt.Sprintf("unknown result %d", this)
	}
}
