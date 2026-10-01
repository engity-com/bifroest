package environment

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/template"
)

type localTemplateTestRequest struct {
	Request
}

func (localTemplateTestRequest) Authorization() authorization.Authorization { return nil }

func (localTemplateTestRequest) GetField(name string) (any, bool, error) {
	if name == "authorization" {
		return map[string]any{"name": "remote-user"}, true, nil
	}
	return nil, false, fmt.Errorf("unknown request field %q", name)
}

type localTemplateTestAccount struct{}

func (localTemplateTestAccount) GetField(name string) (any, bool, error) {
	if name == "name" {
		return "local-user", true, nil
	}
	return nil, false, fmt.Errorf("unknown account field %q", name)
}

func TestLocalTemplateContextKeepsRequestAndAddsCandidate(t *testing.T) {
	ctx := localTemplateContext{Request: localTemplateTestRequest{}, user: localTemplateTestAccount{}, managed: true}
	value, err := template.MustNewString("{{ .authorization.name }}/{{ .user.name }}/{{ .user.managed }}").Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "remote-user/local-user/true", value)

	ctx.managed = false
	managed, err := template.MustNewBool("{{ .user.managed }}").Render(ctx)
	require.NoError(t, err)
	require.False(t, managed)
}

func TestLocalTemplateContextWithoutCandidate(t *testing.T) {
	ctx := localTemplateContext{Request: localTemplateTestRequest{}}
	exists, err := template.MustNewBool("{{ if .user }}true{{ else }}false{{ end }}").Render(ctx)
	require.NoError(t, err)
	require.False(t, exists)
}
