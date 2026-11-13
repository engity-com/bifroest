//go:build windows

package authorization

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

type windowsResumeView struct {
	identity             windowslocal.Account
	home, display, shell string
	gids                 []string
}

func (v *windowsResumeView) Account() windowslocal.Account { return v.identity }
func (v *windowsResumeView) IsEqualTo(other windowslocal.PasswordAccountView) bool {
	value, ok := other.(*windowsResumeView)
	return ok && reflect.DeepEqual(v, value)
}
func (v *windowsResumeView) GetField(name string) (any, bool, error) {
	switch name {
	case "name":
		return v.identity.Name, true, nil
	case "uid":
		return v.identity.SID, true, nil
	case "homeDir":
		return v.home, true, nil
	case "displayName":
		return v.display, true, nil
	case "shell":
		return v.shell, true, nil
	case "gids":
		return append([]string(nil), v.gids...), true, nil
	case "managed":
		return nil, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported fixture field %q", name)
	}
}

type windowsResumeRequest struct {
	*resumeTestRequest
	ctx      context.Context
	resolved Authorization
	validate func(Authorization) (bool, error)
}

func (r *windowsResumeRequest) Context() context.Context                   { return r.ctx }
func (r *windowsResumeRequest) SetAuthorizationContext(auth Authorization) { r.resolved = auth }
func (r *windowsResumeRequest) GetField(name string) (any, bool, error) {
	if name == "authorization" {
		return r.resolved, true, nil
	}
	if name == "remote" {
		return r.Connection().Remote(), true, nil
	}
	return nil, false, fmt.Errorf("unknown fixture field %q", name)
}
func (r *windowsResumeRequest) Validate(auth Authorization) (bool, error) {
	if r.validate != nil {
		return r.validate(auth)
	}
	return true, nil
}

func newWindowsPasswordResumeFixture(t *testing.T, method, remoteName string) (*LocalAuthorizer, *windowsResumeRequest, *windowsResumeView) {
	t.Helper()
	base := newFacadeSelectionRequest(t, remoteName)
	view := &windowsResumeView{identity: windowslocal.Account{Name: "alice", SID: "S-1-5-21-1-2-3-1001"}, home: `C:\Users\alice`, display: "Current Alice", shell: "cmd.exe", gids: []string{"S-1-5-32-545"}}
	raw := []byte(`{"user":{"name":"alice","sid":"S-1-5-21-1-2-3-1001"},"envVars":{"STALE":"not-current"},"groups":["stale"]}`)
	sess, err := base.repository.Create(t.Context(), "selected", authenticationTestRemote(remoteName), raw)
	require.NoError(t, err)
	conf := &configuration.AuthorizationLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.Password.Allowed = template.MustNewBool(`{{ eq .authorization.user.name "alice" }}`)
	conf.Password.InteractiveAllowed = template.BoolOf(true)
	conf.Password.EmptyAllowed = template.BoolOf(false)
	authorizer := &LocalAuthorizer{flow: "selected", conf: conf}
	req := &windowsResumeRequest{resumeTestRequest: &resumeTestRequest{Request: base, sess: sess, identity: authentication.Identity{Principal: "alice", Issuer: "local", Subject: view.identity.SID}, credential: authentication.SessionCredential{Kind: "local", Method: method}, verified: true, selection: connection.Selection{Transport: connection.TransportHttp, Host: "app.example.org", Slug: "Work"}}, ctx: t.Context()}
	return authorizer, req, view
}

func TestWindowsPasswordResumeRevalidatesCurrentAccountWithoutPrimaryReplay(t *testing.T) {
	for _, method := range []string{"password", "keyboard-interactive"} {
		for _, remoteName := range []string{"alice", ""} {
			t.Run(method+"/remote="+remoteName, func(t *testing.T) {
				authorizer, request, view := newWindowsPasswordResumeFixture(t, method, remoteName)
				var policies []bool
				check := func(_ context.Context, account windowslocal.Account, policy windowslocal.PasswordAccountPolicy) (windowslocal.PasswordAccountView, error) {
					require.Equal(t, view.identity, account)
					policies = append(policies, policy.AllowEmpty)
					copy := *view
					copy.gids = append([]string(nil), view.gids...)
					return &copy, nil
				}
				before, err := request.sess.AuthorizationToken(t.Context())
				require.NoError(t, err)
				auth, err := authorizer.resumeWindowsPasswordAccount(request, request.sess, check)
				require.NoError(t, err)
				require.Equal(t, []bool{true, false}, policies)
				require.Equal(t, request.sess.Id(), auth.FindSession().Id())
				require.Equal(t, remoteName, auth.Remote().User())
				require.Nil(t, auth.EnvVars())
				require.Nil(t, auth.(*local).passwordAccount, "request-local metadata must not survive into the access grant or subsequent admissions")
				require.Nil(t, AuthorizedKeyPolicyOf(auth))
				require.Zero(t, request.Request.(*facadeSelectionRequest).prompts)
				require.Equal(t, "wrong", request.Request.(*facadeSelectionRequest).password)
				after, err := request.sess.AuthorizationToken(t.Context())
				require.NoError(t, err)
				require.Equal(t, before, after)
			})
		}
	}
}

func TestWindowsPasswordResumeRejectsPolicyIdentityAndValidationChanges(t *testing.T) {
	for _, scenario := range []string{"password-disabled", "interactive-disabled", "native-denied", "native-unavailable", "null-native", "different-name", "different-sid", "group-drift", "home-drift", "shell-drift", "display-drift", "validation-denied", "validation-error", "disposed-during-validation", "missing-selector", "cancel-during-validation", "empty-denied-after-validation"} {
		t.Run(scenario, func(t *testing.T) {
			method := "password"
			if scenario == "interactive-disabled" {
				method = "keyboard-interactive"
			}
			authorizer, request, view := newWindowsPasswordResumeFixture(t, method, "alice")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request.ctx = ctx
			if scenario == "password-disabled" {
				authorizer.conf.Password.Allowed = template.BoolOf(false)
			}
			if scenario == "interactive-disabled" {
				authorizer.conf.Password.InteractiveAllowed = template.BoolOf(false)
			}
			if scenario == "missing-selector" {
				require.NoError(t, request.sess.SetAuthorizationToken(t.Context(), []byte(`{"user":{"name":"alice"}}`)))
			}
			request.validate = func(Authorization) (bool, error) {
				switch scenario {
				case "validation-denied":
					return false, nil
				case "validation-error":
					return false, errors.New("environment validation failed")
				case "disposed-during-validation":
					_, err := request.sess.Dispose(t.Context())
					require.NoError(t, err)
				case "cancel-during-validation":
					cancel()
				}
				return true, nil
			}
			calls := 0
			check := func(_ context.Context, _ windowslocal.Account, policy windowslocal.PasswordAccountPolicy) (windowslocal.PasswordAccountView, error) {
				calls++
				if scenario == "native-denied" {
					return nil, windowslocal.ErrPasswordAccountPolicyDenied
				}
				if scenario == "native-unavailable" {
					return nil, windowslocal.ErrPasswordAccountPolicyUnavailable
				}
				if scenario == "null-native" {
					return nil, nil
				}
				if scenario == "empty-denied-after-validation" && !policy.AllowEmpty {
					return nil, windowslocal.ErrPasswordAccountPolicyDenied
				}
				copy := *view
				copy.gids = append([]string(nil), view.gids...)
				if scenario == "different-name" {
					copy.identity.Name = "bob"
				}
				if scenario == "different-sid" {
					copy.identity.SID += "1"
				}
				if calls == 2 {
					switch scenario {
					case "group-drift":
						copy.gids = []string{"S-1-5-32-544"}
					case "home-drift":
						copy.home += "-other"
					case "shell-drift":
						copy.shell = "other"
					case "display-drift":
						copy.display = "other"
					}
				}
				return &copy, nil
			}
			auth, err := authorizer.resumeWindowsPasswordAccount(request, request.sess, check)
			require.Nil(t, auth)
			require.Error(t, err)
			if resolved, ok := request.resolved.(*local); ok {
				require.Nil(t, resolved.passwordAccount, "failed validation must clear request-only metadata as well")
			}
			if scenario == "native-unavailable" || scenario == "null-native" {
				require.ErrorIs(t, err, ErrSessionResumeUnavailable)
			}
			if scenario == "cancel-during-validation" {
				require.ErrorIs(t, err, context.Canceled)
			}
			if scenario == "missing-selector" {
				require.Zero(t, calls)
			}
		})
	}
}

func TestWindowsPasswordResumePublicBoundaryDeniesUnverifiedPossession(t *testing.T) {
	authorizer, request, _ := newWindowsPasswordResumeFixture(t, "password", "alice")
	request.verified = false
	request.Request = nil
	auth, err := authorizer.ResumeSession(request)
	require.Nil(t, auth)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
}
