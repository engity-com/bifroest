package environment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

func TestLocalTemplateUsesWindowsAccountFactsWithoutNativeGetters(t *testing.T) {
	t.Setenv("COMSPEC", "must-not-be-read")
	home, shell := `C:\Fixture\Home`, `{{ env "COMSPEC" }}`
	groups := []windowslocal.AccountGroupFacts{{Name: "operators", SID: "S-1-5-32-545"}}
	facts := windowslocal.AccountFacts{Identity: windowslocal.Account{Name: "synthetic", SID: "S-1-5-21-1-2-3-1001"}, HomeDir: &home, Shell: &shell, Groups: &groups}
	account, err := windowslocal.NewAccountSnapshot(facts)
	require.NoError(t, err)
	request := localEvaluationTestRequest{evaluation: template.NewEvaluation(template.EvaluationSources{})}
	ctx := localTemplateContext{Request: request, user: account, managed: true}
	value, err := template.MustNewString(`{{ .user.name }}|{{ .user.uid }}|{{ .user.homeDir }}|{{ .user.shell }}|{{ (index .user.groups 0).name }}|{{ index .user.gids 0 }}|{{ .user.managed }}`).Render(ctx)
	require.NoError(t, err)
	require.Equal(t, `synthetic|S-1-5-21-1-2-3-1001|C:\Fixture\Home|{{ env "COMSPEC" }}|operators|S-1-5-32-545|true`, value)
	// Supplying text containing template syntax must not execute that text.
	// This test runs on Unix too: there is no Windows API behind the view.
	facts.HomeDir, facts.Shell, facts.Groups = nil, nil, nil
	ctx.user, err = windowslocal.NewAccountSnapshot(facts)
	require.NoError(t, err)
	for _, source := range []string{`{{ .user.homeDir | default "fallback" }}`, `{{ .user.shell }}`, `{{ .user.groups }}`, `{{ .user.gids }}`} {
		value, err := template.MustNewString(source).Render(ctx)
		require.ErrorIs(t, err, windowslocal.ErrAccountFieldUnavailable)
		require.Empty(t, value)
	}
}
