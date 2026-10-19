package management

import (
	"bytes"
	"fmt"
	"io"
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
	snapshot := output.String()
	require.Equal(t, string(message[:16<<10]), snapshot)
	written, err = output.Write([]byte("discarded after the limit"))
	require.NoError(t, err)
	require.Equal(t, len("discarded after the limit"), written)
	require.Equal(t, snapshot, output.String())
}

func TestManagementDiagnosticsAllowConcurrentWritesAndReads(t *testing.T) {
	for _, writers := range []int{1, 4} {
		t.Run(fmt.Sprintf("writers=%d", writers), func(t *testing.T) {
			var output diagnosticOutput
			start := make(chan struct{})
			results := make(chan error, writers)
			for range writers {
				go func() {
					<-start
					for range 32768 {
						written, err := output.Write([]byte{'x'})
						if err != nil || written != 1 {
							results <- fmt.Errorf("diagnostic write returned %d, %v", written, err)
							return
						}
					}
					results <- nil
				}()
			}
			close(start)
			for range 2048 {
				require.LessOrEqual(t, len(output.String()), 16<<10)
			}
			for range writers {
				require.NoError(t, <-results)
			}
			require.Equal(t, string(bytes.Repeat([]byte{'x'}, 16<<10)), output.String())
		})
	}
}

type shortDiagnosticOutput struct{}

func (shortDiagnosticOutput) Write(content []byte) (int, error) { return len(content) - 1, nil }

func TestManagementDiagnosticsReportShortWrites(t *testing.T) {
	var diagnostic diagnosticOutput
	_, err := diagnostic.Write([]byte("remote warning\n"))
	require.NoError(t, err)
	require.ErrorIs(t, diagnostic.forwardTo(shortDiagnosticOutput{}), io.ErrShortWrite)
}

func TestRunDirectRejectsCommandsOutsideVersionForms(t *testing.T) {
	for _, command := range []string{
		"sh", "version; id", "version --long=false; id", "version --long=$(id)", "version --long=false --help",
	} {
		err := (Target{}).RunDirect(t.Context(), command)
		require.ErrorContains(t, err, "unsupported direct management command")
	}
}
