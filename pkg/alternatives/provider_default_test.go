//go:build !local_build

package alternatives

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestPublishAlternativeCreatesExecutable(t *testing.T) {
	target := filepath.Join(t.TempDir(), "bifroest")

	require.NoError(t, publishAlternative(target, strings.NewReader("alternative binary")))

	content, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "alternative binary", string(content))
	info, err := os.Stat(target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0755), info.Mode().Perm())
}

func TestPublishAlternativeDoesNotExposePartialDownload(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "bifroest")
	require.NoError(t, os.WriteFile(target, []byte("existing binary"), 0755))

	err := publishAlternative(target, io.MultiReader(strings.NewReader("partial replacement"), failingReader{}))
	require.ErrorContains(t, err, "download failed")

	content, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "existing binary", string(content))
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestFindBinaryMakesCachedAlternativeExecutable(t *testing.T) {
	target := filepath.Join(t.TempDir(), "linux-arm64")
	require.NoError(t, os.WriteFile(target, []byte("cached binary"), 0644))
	p := &provider{
		conf: &configuration.Alternatives{
			Location: template.MustNewString(target),
		},
		version: alternativesTestVersion{},
	}

	actual, err := p.FindBinaryFor(context.Background(), sys.OsLinux, sys.ArchArm64)
	require.NoError(t, err)
	require.Equal(t, target, actual)
	info, err := os.Stat(target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0755), info.Mode().Perm())
}

func TestDefaultProviderRejectsDarwinOciImage(t *testing.T) {
	_, err := (&provider{}).FindOciImageFor(context.Background(), sys.OsDarwin, sys.ArchArm64)
	require.ErrorContains(t, err, "darwin is unsupported for OCI images")
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("download failed")
}

type alternativesTestVersion struct {
	unusedAlternativesTestVersion
}

type unusedAlternativesTestVersion interface{ sys.Version }

func (alternativesTestVersion) Version() string { return "v1.2.3" }
func (alternativesTestVersion) Os() sys.Os      { return sys.OsDarwin }
func (alternativesTestVersion) Arch() sys.Arch  { return sys.ArchArm64 }
