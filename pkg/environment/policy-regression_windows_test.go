//go:build windows

package environment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
)

// Only invalid selectors are evaluated here: every case stops before any native
// SAM lookup. Successful native account resolution is not covered by these tests.
func TestPolicyRegressionWindowsLocalSelectorValidation(t *testing.T) {
	for _, test := range []struct{ name, sid string }{
		{"", ""}, {`DOMAIN\private-secret`, ""}, {"private-secret@domain", ""}, {"fixture", "private-secret-invalid-SID"},
		{`{{ fail "private-secret" }}`, ""},
	} {
		conf := &configuration.EnvironmentLocal{}
		conf.Name, conf.Uid = template.MustNewString(test.name), template.MustNewString(test.sid)
		_, err := (&LocalRepository{conf: conf}).ResolveSessionTarget(targetTestContext{ctx: t.Context()})
		require.Error(t, err)
		require.NotContains(t, err.Error(), "private-secret")
		require.True(t, berrors.Config.IsErr(err))
	}
	conf := &configuration.EnvironmentLocal{}
	conf.Name = template.MustNewString(`private-secret\invalid`)
	_, _, _, err := (&LocalRepository{conf: conf}).lookupConfiguredAccount(targetTestContext{ctx: t.Context()})
	require.EqualError(t, err, "invalid local SAM account name")
	require.True(t, berrors.Config.IsErr(err))
	require.NotContains(t, err.Error(), "private-secret")
}

func TestPolicyRegressionEnvironmentSAMNameRules(t *testing.T) {
	for _, name := range []string{"alice", "some user", "Müller", "a$"} {
		require.True(t, validLocalSAMName(name))
	}
	for _, name := range []string{"", ".", "..", `host\alice`, "alice@host", "alice.", "\xff"} {
		require.False(t, validLocalSAMName(name))
	}
}
