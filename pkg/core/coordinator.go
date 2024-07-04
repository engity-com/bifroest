package core

import (
	"context"

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
	OnUserInfoReceived  func(token *oidc2.UserInfo) error
}

func (this *Coordinator) Run(ctx context.Context, requestedUserName string) (*user.User, error) {
	fail := func(err error) (*user.User, error) {
		return nil, err
	}

	if ctx == nil {
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = this.Configuration.ToContext()
		defer cancelFunc()
	}

	if v := this.Configuration.Pam.AllowedUserName; !v.IsZero() && !v.MatchString(requestedUserName) {
		return nil, nil
	}
	if v := this.Configuration.Pam.ForbiddenUserName; !v.IsZero() && v.MatchString(requestedUserName) {
		return nil, nil
	}

	token, userInfo, err := this.remoteAuthorize(ctx)
	if err != nil {
		return fail(err)
	}

	req, err := this.toUserRequirement(token, userInfo)
	if err != nil {
		return fail(err)
	}

	u, err := this.ensureUser(req)
	if err != nil {
		return fail(err)
	}

	return u, nil
}

func (this *Coordinator) remoteAuthorize(ctx context.Context) (*oauth2.Token, *oidc2.UserInfo, error) {
	fail := func(err error) (*oauth2.Token, *oidc2.UserInfo, error) {
		return nil, nil, err
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

	token, err := client.RetrieveDeviceAuthToken(ctx, dar)
	if err != nil {
		return fail(err)
	}

	if cb := this.OnTokenReceived; cb != nil {
		if err := cb(token); err != nil {
			return fail(err)
		}
	}

	userInfo, err := client.GetUserInfo(ctx, token)
	if err != nil {
		return fail(err)
	}

	if cb := this.OnUserInfoReceived; cb != nil {
		if err := cb(userInfo); err != nil {
			return fail(err)
		}
	}

	return token, userInfo, nil
}

func (this *Coordinator) toUserRequirement(token *oauth2.Token, userInfo *oidc2.UserInfo) (*user.Requirement, error) {
	fail := func(err error) (*user.Requirement, error) {
		return nil, err
	}
	failf := func(message string, args ...any) (*user.Requirement, error) {
		return fail(errors.Newf(errors.TypeConfig, message, args...))
	}

	data := coordinatorContextResolveUserRequirement{
		Oidc: coordinatorContextOidc{
			Token:    token,
			UserInfo: userInfo,
		},
	}

	req, err := this.Configuration.User.Render(common.StructuredKeyOf("user"), data)
	if err != nil {
		return failf("cannot render user requirement based oidc information: %w", err)
	}

	return &req, nil
}

func (this *Coordinator) ensureUser(req *user.Requirement) (*user.User, error) {
	fail := func(err error) (*user.User, error) {
		return nil, err
	}
	failf := func(message string, args ...any) (*user.User, error) {
		return fail(errors.Newf(errors.TypeSystem, message, args...))
	}

	u, err := this.UserEnsurer.Ensure(req, &user.EnsureOpts{
		CreateAllowed: &this.Configuration.User.CreateIfAbsent,
		ModifyAllowed: &this.Configuration.User.UpdateIfDifferent,
	})
	if err != nil {
		return failf("cannot ensure user %v: %w", req, u)
	}

	return u, nil
}

type coordinatorContextResolveUserRequirement struct {
	Oidc coordinatorContextOidc
}

type coordinatorContextOidc struct {
	Token    *oauth2.Token
	UserInfo *oidc2.UserInfo
}
