package nanoserver

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	bib "github.com/engity-com/bifroest/internal/build"
)

const (
	serverCore2022 = "mcr.microsoft.com/windows/servercore:ltsc2022@sha256:f1a914079973258061ddbc95a9af579eab2ee252a6fddb254b1be5d769761acd"
	nanoServer2025 = "mcr.microsoft.com/windows/nanoserver:ltsc2025@sha256:5c42e42b31816a3a7619cb71b4f14353793a47293e198dbde8fe4fce2c8935cb"
	serverCore2025 = "mcr.microsoft.com/windows/servercore:ltsc2025@sha256:a43c2d41a3d6e940dec865731e2f5db5c3e03f705f5300ef0b5817d3e01ecfb1"
)

type windowsContainerImages struct {
	nano, serverCore string
}

func windowsContainerImagesFor(version string) (windowsContainerImages, error) {
	switch version {
	case "", "2022":
		return windowsContainerImages{bib.DefaultWindowsContainerBaseImage(), serverCore2022}, nil
	case "2025":
		return windowsContainerImages{nanoServer2025, serverCore2025}, nil
	default:
		return windowsContainerImages{}, fmt.Errorf("unsupported Windows container release %q", version)
	}
}

func TestWindowsContainerImagesKeep2022DefaultAndPinBothReleases(t *testing.T) {
	defaults, err := windowsContainerImagesFor("")
	require.NoError(t, err)
	require.Equal(t, bib.DefaultWindowsContainerBaseImage(), defaults.nano)
	for _, version := range []string{"2022", "2025"} {
		t.Run(version, func(t *testing.T) {
			images, err := windowsContainerImagesFor(version)
			require.NoError(t, err)
			if version == "2022" {
				require.Equal(t, defaults, images)
			}
			for repository, image := range map[string]string{"nanoserver": images.nano, "servercore": images.serverCore} {
				digest, err := name.NewDigest(image, name.StrictValidation)
				require.NoError(t, err)
				require.Equal(t, "mcr.microsoft.com/windows/"+repository, digest.Repository.Name())
				require.Contains(t, image, ":ltsc"+version+"@sha256:")
			}
		})
	}
	_, err = windowsContainerImagesFor("latest")
	require.ErrorContains(t, err, "unsupported Windows container release")
}

func TestWindowsContainerWorkflowRunsBothReleasesIndependently(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "nanoserver.yml"))
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]struct {
			RunsOn          string `yaml:"runs-on"`
			ContinueOnError any    `yaml:"continue-on-error"`
			Strategy        struct {
				FailFast *bool `yaml:"fail-fast"`
				Matrix   struct {
					Windows []string `yaml:"windows"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
			Env   map[string]string `yaml:"env"`
			Steps []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	job, exists := workflow.Jobs["windows-local"]
	require.True(t, exists)
	require.Equal(t, []string{"2022", "2025"}, job.Strategy.Matrix.Windows)
	require.NotNil(t, job.Strategy.FailFast)
	require.False(t, *job.Strategy.FailFast, "a 2022 failure must not cancel the 2025 comparison")
	require.Nil(t, job.ContinueOnError, "both supported releases must report failures")
	require.Equal(t, "windows-${{ matrix.windows }}", job.RunsOn)
	require.Equal(t, "${{ matrix.windows }}", job.Env["BIFROEST_TEST_NANOSERVER_VERSION"])
	require.Equal(t, "process", job.Env["BIFROEST_TEST_NANOSERVER_ISOLATION"])
	uploads := 0
	for _, step := range job.Steps {
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
			uploads++
			require.Equal(t, "native-windows-browser-${{ matrix.windows }}", step.With["name"])
		}
	}
	require.Equal(t, 1, uploads)
}
