package management

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/format"
)

func TestSelectOutputFormatKeepsCommandAndFilters(t *testing.T) {
	for _, test := range []struct {
		args   []string
		format format.Format
		wire   []string
	}{
		{[]string{"session", "ls", "--state=all"}, format.Text, []string{"session", "ls", "--state=all"}},
		{[]string{"flow", "--format=yaml", "show", "production"}, format.Yaml, []string{"flow", "show", "production"}},
		{[]string{"session", "ls", "--format", "json", "--user=alice"}, format.Json, []string{"session", "ls", "--user=alice"}},
	} {
		format, wire, err := selectOutputFormat(test.args)
		require.NoError(t, err)
		require.Equal(t, test.format, format)
		require.Equal(t, test.wire, wire)
	}
	_, _, err := selectOutputFormat([]string{"flow", "ls", "--format=xml"})
	require.ErrorContains(t, err, "invalid")
}

func TestManagementDiagnosticsRemainBoundedWithoutBlockingSSH(t *testing.T) {
	var output diagnosticOutput
	message := bytes.Repeat([]byte{'x'}, 1<<20)
	written, err := output.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), written)
	require.Len(t, output.Bytes(), 16<<10)
}

func TestRunDirectRejectsCommandsOutsideVersionForms(t *testing.T) {
	for _, command := range []string{
		"sh", "version; id", "version --long=false; id", "version --long=$(id)", "version --long=false --help",
	} {
		err := (Target{}).RunDirect(t.Context(), command)
		require.ErrorContains(t, err, "unsupported direct management command")
	}
}
