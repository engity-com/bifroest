//go:build unix

package environment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestLocalTemplateUsesUnixAccountFactsAndNumericIdentities(t *testing.T) {
	uid := user.Id(1234)
	home, shell := "/fixture/home", "/bin/sh"
	groups := user.Groups{{Name: "operators", Gid: 3000}}
	facts := user.AccountFacts{Name: "synthetic", Uid: &uid, Group: &user.Group{Name: "primary", Gid: 2000}, Groups: &groups, Shell: &shell, HomeDir: &home}
	account, err := user.NewSnapshot(facts)
	require.NoError(t, err)
	ctx := localTemplateContext{Request: localEvaluationTestRequest{evaluation: template.NewEvaluation(template.EvaluationSources{})}, user: account, managed: false}
	value, err := template.MustNewString(`{{ if eq .user.uid 1234 }}{{ .user.name }}{{ end }}|{{ .user.group.name }}|{{ .user.gid }}|{{ .user.homeDir }}|{{ .user.shell }}|{{ (index .user.groups 0).name }}|{{ index .user.gids 0 }}|{{ .user.managed }}`).Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "synthetic|primary|2000|/fixture/home|/bin/sh|operators|3000|false", value)
	facts.Groups = nil
	ctx.user, err = user.NewSnapshot(facts)
	require.NoError(t, err)
	_, err = template.MustNewBool(`{{ if .user.groups }}true{{ else }}false{{ end }}`).Render(ctx)
	require.ErrorIs(t, err, user.ErrAccountFieldUnavailable, "unmodeled groups must not become an unmanaged/empty-group assumption")
}
