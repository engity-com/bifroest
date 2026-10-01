package main

import (
	"iter"
	"os"
	osExec "os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestVersion_releaseNames(t *testing.T) {
	for _, plain := range []string{"v0.0.0", "v1.0.0", "v1.0.0-alpha1", "v1.0.0-alpha10", "v1.0.0-beta1", "v1.0.0-beta10"} {
		t.Run(plain, func(t *testing.T) {
			var v version
			require.NoError(t, v.Set(plain))
			require.NotNil(t, v.semver)
		})
	}
	for _, plain := range []string{"v1.0.0-alpha0", "v1.0.0-beta01", "v1.0.0-alpha.1", "v1.0.0-beta.1", "v1.0.0-rc1", "v1.0.0+meta", "v01.0.0", "v1.00.0", "v1.0.00"} {
		t.Run(plain, func(t *testing.T) {
			var v version
			require.Error(t, v.Set(plain))
		})
	}
}

func TestReleaseWorkflow_versionAndStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release workflow uses Bash")
	}
	content, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(content, &workflow))
	var script string
	for _, step := range workflow.Jobs["evaluate"].Steps {
		if step.Name == "Resolve release version" {
			script = step.Run
		}
	}
	require.NotEmpty(t, script)
	script = `gh() {
  if [[ "$1" != api || "$2" != "repos/${GITHUB_REPOSITORY}/releases/tags/${TEST_RELEASE_TAG}" ]]; then return 1; fi
  if [[ -z "$TEST_RELEASE_STATE" ]]; then return 1; fi
  printf '%s\n' "$TEST_RELEASE_STATE"
}
` + script
	for _, tc := range []struct {
		tag, state, event string
		valid             bool
	}{
		{"v1.0.0", "false\tfalse", "release", true},
		{"v1.0.0-alpha1", "false\ttrue", "release", true},
		{"v1.0.0-beta12", "false\ttrue", "workflow_dispatch", true},
		{"v1.0.0-beta1", "false\tfalse", "release", false},
		{"v1.0.0", "false\ttrue", "workflow_dispatch", false},
		{"v1.0.0-alpha1", "true\ttrue", "release", false},
		{"v1.0.0-beta1", "", "release", false},
		{"v1.0.0-rc1", "false\ttrue", "release", false},
		{"v1.0.0-alpha.1", "false\ttrue", "release", false},
		{"v1.0.0-beta01", "false\ttrue", "release", false},
	} {
		t.Run(tc.tag+"/"+tc.event+"/"+tc.state, func(t *testing.T) {
			cmd := osExec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(),
				"EVENT_NAME="+tc.event, "RELEASE_EVENT_TAG="+tc.tag, "VERSION_INPUT="+tc.tag,
				"TEST_RELEASE_TAG="+tc.tag, "TEST_RELEASE_STATE="+tc.state,
				"GITHUB_REPOSITORY=engity-com/bifroest", "GITHUB_OUTPUT="+os.DevNull,
			)
			output, err := cmd.CombinedOutput()
			if tc.valid {
				require.NoError(t, err, string(output))
			} else {
				require.Error(t, err, string(output))
			}
		})
	}
}

func TestVersion_evaluateLatest(t *testing.T) {
	var instance version

	require.NoError(t, instance.Set("v2.3.4"))

	cases := []struct {
		input []string

		expectedMajor bool
		expectedMinor bool
		expectedPatch bool
	}{{
		input:         a[string](),
		expectedMajor: true,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4"),
		expectedMajor: true,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "1.2.3"),
		expectedMajor: true,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "1.2.3", "2.3.3"),
		expectedMajor: true,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "1.2.3", "3.0.0"),
		expectedMajor: false,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "1.2.3", "3.0.0", "2.3.3"),
		expectedMajor: false,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "1.2.3", "3.1.0", "2.3.3"),
		expectedMajor: false,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "1.2.3", "2.3.5"),
		expectedMajor: false,
		expectedMinor: false,
		expectedPatch: false,
	}, {
		input:         a[string]("2.3.4", "1.2.3", "2.4.0"),
		expectedMajor: false,
		expectedMinor: false,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "3.0.0-beta1"),
		expectedMajor: true,
		expectedMinor: true,
		expectedPatch: true,
	}}

	for _, c := range cases {
		t.Run(strings.Join(c.input, ","), func(t *testing.T) {
			given := instance.cleanClone()

			actualErr := given.evaluateLatest(allSemver(c.input...))
			require.NoError(t, actualErr)
			assert.Equal(t, c.expectedMajor, given.latestMajor)
			assert.Equal(t, c.expectedMinor, given.latestMinor)
			assert.Equal(t, c.expectedPatch, given.latestPatch)
		})
	}
}

func TestVersion_prereleaseTags(t *testing.T) {
	for _, plain := range []string{"v1.0.0-alpha1", "v1.0.0-beta1"} {
		t.Run(plain, func(t *testing.T) {
			var v version
			require.NoError(t, v.Set(plain))
			require.NoError(t, v.evaluateLatest(allSemver("0.7.7")))
			assert.Equal(t, []string{"generic-" + plain[1:]}, slices.Collect(v.tags("generic-", "generic")))
			assert.Equal(t, []string{plain[1:]}, slices.Collect(v.tags("", "latest")))
		})
	}
}

func TestVersion_stableTagsAfterPrerelease(t *testing.T) {
	var v version
	require.NoError(t, v.Set("v0.8.0"))
	require.NoError(t, v.evaluateLatest(allSemver("0.7.7", "1.0.0-beta1")))
	assert.Equal(t, []string{"0.8.0", "0.8", "0", "latest"}, slices.Collect(v.tags("", "latest")))
	assert.Equal(t, []string{"extended-0.8.0", "extended-0.8", "extended-0", "extended"}, slices.Collect(v.tags("extended-", "extended")))
}

func TestVersion_tags_semver(t *testing.T) {
	var instance version

	require.NoError(t, instance.Set("v2.3.4"))

	cases := []struct {
		major bool
		minor bool
		patch bool
		root  string

		outputs []string
	}{{
		major:   false,
		minor:   false,
		patch:   false,
		root:    "ll",
		outputs: a("x2.3.4"),
	}, {
		major:   false,
		minor:   false,
		patch:   true,
		root:    "ll",
		outputs: a("x2.3.4", "x2.3"),
	}, {
		major:   false,
		minor:   true,
		patch:   true,
		root:    "ll",
		outputs: a("x2.3.4", "x2.3", "x2"),
	}, {
		major:   true,
		minor:   true,
		patch:   true,
		root:    "ll",
		outputs: a("x2.3.4", "x2.3", "x2", "ll"),
	}, {
		major:   true,
		minor:   true,
		patch:   false,
		root:    "ll",
		outputs: a("x2.3.4"),
	}, {
		major:   true,
		minor:   false,
		patch:   true,
		root:    "ll",
		outputs: a("x2.3.4", "x2.3"),
	}}

	for _, c := range cases {
		t.Run(strings.Join(c.outputs, ","), func(t *testing.T) {
			given := instance.cleanClone()
			given.latestMajor = c.major
			given.latestMinor = c.minor
			given.latestPatch = c.patch

			actual := slices.Collect(given.tags("x", c.root))
			assert.Equal(t, c.outputs, actual)
		})
	}
}

func TestVersion_tags_other(t *testing.T) {
	cases := []struct {
		input   string
		prefix  string
		root    string
		outputs []string
	}{{
		input:   "x123x",
		prefix:  "p",
		root:    "r",
		outputs: a("px123x"),
	}, {
		input:   "v1.2.3",
		prefix:  "p",
		root:    "r",
		outputs: a("p1.2.3"),
	}}

	for _, c := range cases {
		t.Run(c.input+"-"+c.prefix+"-"+c.root, func(t *testing.T) {
			var instance version
			require.NoError(t, instance.Set(c.input))

			actual := slices.Collect(instance.tags(c.prefix, c.root))
			assert.Equal(t, c.outputs, actual)
		})
	}
}

func a[T any](in ...T) []T {
	return in
}

func allSemver(in ...string) iter.Seq2[*semver.Version, error] {
	return func(yield func(*semver.Version, error) bool) {
		for _, plain := range in {
			if !yield(semver.MustParse(plain), nil) {
				return
			}
		}
	}
}

func (this version) cleanClone() version {
	return version{
		this.semver,
		this.raw,
		false,
		false,
		false,
	}
}
