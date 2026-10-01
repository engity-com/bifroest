//go:build !local_build

package alternatives

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestFindBinaryDownloadsExecutableAlternative(t *testing.T) {
	target := filepath.Join(t.TempDir(), "bifroest")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("alternative binary"))
	}))
	t.Cleanup(server.Close)
	p := &provider{
		conf: &configuration.Alternatives{
			Location:    template.MustNewString(target),
			DownloadUrl: template.MustNewUrl(server.URL + "/bifroest"),
		},
		version: alternativesTestVersion{},
	}

	actual, err := p.FindBinaryFor(context.Background(), sys.OsLinux, sys.ArchArm64)
	require.NoError(t, err)
	require.Equal(t, target, actual)

	content, err := os.ReadFile(actual)
	require.NoError(t, err)
	require.Equal(t, "alternative binary", string(content))
	info, err := os.Stat(actual)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0755), info.Mode().Perm())
	}
}

func TestDefaultProviderRejectsDarwinOciImage(t *testing.T) {
	_, err := (&provider{}).FindOciImageFor(context.Background(), sys.OsDarwin, sys.ArchArm64)
	require.ErrorContains(t, err, "darwin is unsupported for OCI images")
}

type alternativesTestVersion struct {
	unusedAlternativesTestVersion
}

type unusedAlternativesTestVersion interface{ sys.Version }

func (alternativesTestVersion) Version() string { return "v1.2.3" }
func (alternativesTestVersion) Os() sys.Os      { return sys.OsDarwin }
func (alternativesTestVersion) Arch() sys.Arch  { return sys.ArchArm64 }
