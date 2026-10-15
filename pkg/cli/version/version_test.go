package version

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

type testVersion struct{}

func (testVersion) Title() string                 { return "Bifröst" }
func (testVersion) Version() string               { return "1.2.3" }
func (testVersion) Revision() string              { return "abc" }
func (testVersion) Edition() sys.Edition          { return 0 }
func (testVersion) BuildAt() time.Time            { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
func (testVersion) Vendor() string                { return "test" }
func (testVersion) GoVersion() string             { return "go1.27" }
func (testVersion) Os() sys.Os                    { return sys.OsLinux }
func (testVersion) Arch() sys.Arch                { return sys.ArchAmd64 }
func (testVersion) Features() sys.VersionFeatures { return noFeatures{} }

type noFeatures struct{}

func (noFeatures) ForEach(func(sys.VersionFeatureCategory)) {}

func TestVersionReusesApplicationAndContextStreams(t *testing.T) {
	requirement := cli.NewSimpleApplication().WithName("bifroest").WithFallbackToStdio(false).WithErrorHandlerEnabled(false)
	Register(t.Context(), requirement, common.UsageManagement, testVersion{})
	app, err := requirement.Create()
	require.NoError(t, err)
	defer func() { require.NoError(t, app.Close()) }()
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"version"}, "Bifröst 1.2.3"},
		{[]string{"version", "--long"}, "Version:  1.2.3"},
		{[]string{"version"}, "Bifröst 1.2.3"},
	} {
		var output, diagnostics bytes.Buffer
		ctx := cli.ContextWithStdio(context.Background(), nil, &output, &diagnostics)
		require.NoError(t, app.ParseAndExecute(ctx, nil, test.args...))
		require.Contains(t, output.String(), test.want)
		require.Empty(t, diagnostics.String())
		if len(test.args) == 1 {
			require.False(t, strings.Contains(output.String(), "Version:"))
		}
	}
}
