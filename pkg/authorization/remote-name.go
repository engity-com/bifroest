package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func sessionUserNameIs(expected string) func(context.Context, session.Session) (bool, error) {
	return func(ctx context.Context, candidate session.Session) (bool, error) {
		raw, err := candidate.AuthorizationToken(ctx)
		if err != nil {
			return false, err
		}
		var selector struct {
			User struct {
				Name string `json:"name"`
			} `json:"user"`
		}
		return json.Unmarshal(raw, &selector) == nil && expected != "" && selector.User.Name == expected, nil
	}
}

func checkMappedResumeRemote(req Request, candidate session.Session, value template.String) error {
	if !hasRemoteNameMapping(value) {
		return nil
	}
	info, err := candidate.Info(req.Context())
	if err != nil {
		return err
	}
	last, err := info.LastAccessed(req.Context())
	if err != nil {
		return err
	}
	if last.Remote().User() != req.Connection().Remote().User() {
		return ErrSessionResumeDenied
	}
	return nil
}

func hasRemoteNameMapping(value template.String) bool {
	return !value.IsZero() && value.String() != configuration.DefaultAuthorizationRemoteName.String()
}

// Resolve once, before credential lookup/validation. Never mutate the transport
// remote: flow filters, audit, recording and session selectors need that name.
func resolveRemoteName(req Request, value template.String) (string, error) {
	if !hasRemoteNameMapping(value) {
		return req.Connection().Remote().User(), nil
	}
	if ctx := req.Context(); ctx != nil && ctx.Err() != nil {
		return "", ctx.Err()
	}
	name, err := value.Render(remoteNameRequest{req})
	if err != nil {
		// Templates can access credentials in the authorization request. Never
		// retain their execution error, arguments or cause in diagnostics.
		return "", errors.New("cannot evaluate authorization remoteName")
	}
	if err := (authentication.Identity{Principal: name, Issuer: "remoteName", Subject: name}).Validate(); err != nil {
		return "", errors.New("authorization remoteName produced an invalid account name")
	}
	if ctx := req.Context(); ctx != nil && ctx.Err() != nil {
		return "", ctx.Err()
	}
	return name, nil
}

type remoteNameRequest struct{ Request }

func (r remoteNameRequest) GetField(name string) (any, bool, error) {
	switch name {
	case "remote":
		return remoteNameRemote{r.Connection().Remote()}, true, nil
	case "connection":
		view, err := connection.TemplateViewOf(r.Request)
		return view, true, err
	default:
		if fields, ok := r.Request.(interface {
			GetField(string) (any, bool, error)
		}); ok {
			return fields.GetField(name)
		}
		return nil, false, fmt.Errorf("authorization request field %q is unavailable", name)
	}
}

type remoteNameRemote struct{ net.Remote }

func (r remoteNameRemote) GetField(name string) (any, bool, error) {
	switch name {
	case "user":
		return r.User(), true, nil
	case "host":
		return r.Host(), true, nil
	default:
		if fields, ok := r.Remote.(interface {
			GetField(string) (any, bool, error)
		}); ok {
			return fields.GetField(name)
		}
		return nil, false, fmt.Errorf("remote field %q is unavailable", name)
	}
}
