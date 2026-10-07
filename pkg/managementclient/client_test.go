package managementclient

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/management"
)

func TestSelectOutputFormatKeepsCommandAndFilters(t *testing.T) {
	for _, test := range []struct {
		args   []string
		format management.Format
		wire   []string
	}{
		{[]string{"session", "ls", "--state=all"}, management.FormatTable, []string{"session", "ls", "--state=all"}},
		{[]string{"flow", "--format=yaml", "show", "production"}, management.FormatYAML, []string{"flow", "show", "production"}},
		{[]string{"session", "ls", "--format", "json", "--user=alice"}, management.FormatJSON, []string{"session", "ls", "--user=alice"}},
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
