package connection_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

// A request can expose the common context without implementing an SSH context
// or manufacturing SSH metadata for a different incoming protocol.
type plainRequest struct{ ctx context.Context }

func (this plainRequest) Context() context.Context                      { return this.ctx }
func (plainRequest) Connection() connection.Connection                  { return nil }
func (plainRequest) Authorization() authorization.Authorization         { return authorization.Forbidden(nil) }
func (plainRequest) Sessions() session.Repository                       { return nil }
func (plainRequest) Validate(authorization.Authorization) (bool, error) { return false, nil }
func (plainRequest) GetField(name string) (any, bool, error) {
	if name == "authorization" {
		return authorization.Forbidden(nil), true, nil
	}
	return nil, false, nil
}

var (
	_ connection.Context    = plainRequest{}
	_ authorization.Request = plainRequest{}
	_ environment.Context   = plainRequest{}
)

func TestPlainContextPreservesLifetimeAndTemplateAccess(t *testing.T) {
	type valueKey struct{}
	ctx, cancel := context.WithCancelCause(context.WithValue(context.Background(), valueKey{}, "request-value"))
	defer cancel(nil)
	request := plainRequest{ctx: ctx}
	require.Equal(t, "request-value", request.Context().Value(valueKey{}))
	result, err := template.MustNewString("{{ .authorization.isAuthorized }}").Render(request)
	require.NoError(t, err)
	require.Equal(t, "false", result)
	cause := errors.New("connection closed")
	cancel(cause)
	require.ErrorIs(t, request.Context().Err(), context.Canceled)
	require.ErrorIs(t, context.Cause(request.Context()), cause)
}
