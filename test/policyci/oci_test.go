package main

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/sys"

	"github.com/stretchr/testify/require"
)

func validContainerInspection() containerInspection {
	var actual containerInspection
	actual.ID = strings.Repeat("a", 64)
	actual.Image = "sha256:" + strings.Repeat("b", 64)
	actual.Config.User, actual.Config.WorkingDir = "1000:1000", "/workspace"
	actual.Config.Entrypoint, actual.Config.Cmd = []string{"/bifroest"}, []string{"test", "pkg/test/examples/ssh"}
	actual.Config.Env = []string{"PATH=/", "TMPDIR=/tmp"}
	actual.Config.Labels = map[string]string{ociRunLabel: "owned"}
	actual.HostConfig.NetworkMode, actual.HostConfig.ReadonlyRootfs = "none", true
	actual.HostConfig.CapDrop, actual.HostConfig.SecurityOpt = []string{"ALL"}, []string{"no-new-privileges"}
	actual.HostConfig.Tmpfs = map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=16m,mode=1777"}
	actual.HostConfig.PidsLimit, actual.HostConfig.Memory, actual.HostConfig.NanoCpus = 64, 256<<20, 1_000_000_000
	actual.Mounts = append(actual.Mounts, struct {
		Type, Source, Destination string
		RW                        bool
	}{"bind", "/host/input", "/workspace", false}, struct {
		Type, Source, Destination string
		RW                        bool
	}{"bind", "/host/output", "/reports", true})
	return actual
}

func TestOCIInspectionRequiresEffectiveRestrictionsNotJustCommandFlags(t *testing.T) {
	check := func(value containerInspection) error {
		return validateContainer(value, []string{"/bifroest"}, []string{"test", "pkg/test/examples/ssh"}, "/host/input", "/host/output", "1000:1000", 0)
	}
	require.NoError(t, check(validContainerInspection()))
	for name, mutate := range map[string]func(*containerInspection){
		"network":           func(v *containerInspection) { v.HostConfig.NetworkMode = "host" },
		"root":              func(v *containerInspection) { v.Config.User = "0:0" },
		"rootfs":            func(v *containerInspection) { v.HostConfig.ReadonlyRootfs = false },
		"privileged":        func(v *containerInspection) { v.HostConfig.Privileged = true },
		"capabilities":      func(v *containerInspection) { v.HostConfig.CapAdd = []string{"SYS_ADMIN"} },
		"cap-drop":          func(v *containerInspection) { v.HostConfig.CapDrop = nil },
		"new-privileges":    func(v *containerInspection) { v.HostConfig.SecurityOpt = nil },
		"read-only-input":   func(v *containerInspection) { v.Mounts[0].RW = true },
		"read-write-report": func(v *containerInspection) { v.Mounts[1].RW = false },
		"socket":            func(v *containerInspection) { v.Mounts[1].Destination = "/var/run/docker.sock" },
		"wrong-fixture":     func(v *containerInspection) { v.Mounts[0].Source = "/different" },
		"entrypoint":        func(v *containerInspection) { v.Config.Entrypoint = []string{"/probe"} },
		"default-run":       func(v *containerInspection) { v.Config.Cmd = []string{"run"} },
		"secrets":           func(v *containerInspection) { v.Config.Env = append(v.Config.Env, "GITHUB_TOKEN=secret") },
		"oom":               func(v *containerInspection) { v.State.OOMKilled = true },
		"exit":              func(v *containerInspection) { v.State.ExitCode = 1 },
		"tmp-size":          func(v *containerInspection) { v.HostConfig.Tmpfs["/tmp"] = "rw,noexec,nosuid,nodev" },
		"pids":              func(v *containerInspection) { v.HostConfig.PidsLimit = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			value := validContainerInspection()
			mutate(&value)
			require.Error(t, check(value))
		})
	}
}

func TestPodmanExpandedCapabilityDropRequiresExplicitEmptyEffectiveAndBoundingSets(t *testing.T) {
	actual := validContainerInspection()
	actual.HostConfig.CapDrop = []string{"CAP_CHOWN", "CAP_SETUID"}
	actual.EffectiveCaps, actual.BoundingCaps = json.RawMessage(`null`), json.RawMessage(`[]`)
	actual.Config.Hostname = actual.ID[:12]
	actual.Config.Env = append(actual.Config.Env, "container=podman", "HOME=/workspace", "HOSTNAME="+actual.Config.Hostname)
	check := func() error {
		return validateContainer(actual, []string{"/bifroest"}, []string{"test", "pkg/test/examples/ssh"}, "/host/input", "/host/output", "1000:1000", 0)
	}
	require.NoError(t, check())
	actual.BoundingCaps = nil
	require.Error(t, check(), "missing fields are not proof of empty capability sets")
	actual.BoundingCaps = json.RawMessage(`["CAP_SYS_ADMIN"]`)
	require.Error(t, check())
	actual.BoundingCaps = json.RawMessage(`[]`)
	actual.Config.Env = append(actual.Config.Env, "HOME=/host/private")
	require.Error(t, check(), "runtime metadata must not permit arbitrary host values")
}

func TestOCIInspectionNeverAuthorizesCleanupOfUnrelatedContainers(t *testing.T) {
	actual := validContainerInspection()
	raw, err := json.Marshal([]containerInspection{actual})
	require.NoError(t, err)
	owned, err := inspectContainer(raw, "owned", actual.Image)
	require.NoError(t, err)
	require.NotNil(t, owned)
	for _, test := range []struct{ token, image string }{{"foreign", actual.Image}, {"owned", "sha256:" + strings.Repeat("c", 64)}} {
		owned, err := inspectContainer(raw, test.token, test.image)
		require.Error(t, err)
		require.Nil(t, owned)
	}
}

func TestOCIArgumentsKeepEntrypointAndSeparateReadOnlyInputsFromReports(t *testing.T) {
	args := containerArguments("docker", "unique", "nonce", "sha256:image", "linux/amd64", "/input, with spaces", "/reports, with spaces", "1000:1000", []string{"test", "pkg/test/examples/ssh"})
	joined := strings.Join(args, "\n")
	for _, required := range []string{"--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"} {
		require.Contains(t, args, required)
	}
	for _, forbidden := range []string{"--entrypoint", "--privileged", "--publish", "docker.sock", "GITHUB_TOKEN"} {
		require.NotContains(t, joined, forbidden)
	}
	require.Equal(t, []string{"sha256:image", "test", "pkg/test/examples/ssh"}, args[len(args)-3:])
	fields, err := csv.NewReader(strings.NewReader(bindMount("/input, with spaces", "/workspace", true))).Read()
	require.NoError(t, err)
	require.Equal(t, []string{"type=bind", "src=/input, with spaces", "dst=/workspace", "readonly"}, fields)
	require.Equal(t, []string{"test", "/reports/nested/report.xml", "literal/host/report/value"}, mapReportArguments([]string{"test", "/host/report/nested/report.xml", "literal/host/report/value"}, "/host/report"))
}

func TestParityNormalizationNeverRewritesAssertionValuesReasonsOrCounters(t *testing.T) {
	document := jsonReport{Results: []jsonResult{{Source: "/host/workspace/case_bftest.lua", Name: "case", Status: "failed", DurationSeconds: .123, Failures: []jsonFailure{{Line: 7, Expected: "/host/workspace/value", Actual: "different", Reason: "/host/workspace/reason"}}}}, Summary: counts{Failed: 1}, DurationSeconds: .5}
	normalized := normalizeJSON(document, "/host/workspace")
	require.Equal(t, "/workspace/case_bftest.lua", normalized.Results[0].Source)
	require.Zero(t, normalized.Results[0].DurationSeconds)
	require.Equal(t, "/host/workspace/value", normalized.Results[0].Failures[0].Expected)
	require.Equal(t, "/host/workspace/reason", normalized.Results[0].Failures[0].Reason)
	require.Equal(t, counts{Failed: 1}, normalized.Summary)
	require.Equal(t, "/host/workspace-other/file", normalizedSource("/host/workspace-other/file", "/host/workspace"))
	text := "--- FAIL: case (0.123s, 1 assertion)\nexpected (0.123s, actual /host/workspace/value\n"
	require.Equal(t, "--- FAIL: case (<duration>s, 1 assertion)\nexpected (0.123s, actual /host/workspace/value\n", normalizeText(text, "/host/workspace"))
	require.Equal(t, "--- PASS: name(0.123s,value) (<duration>s, 1 assertion)", normalizeText("--- PASS: name(0.123s,value) (0.456s, 1 assertion)", "/host/workspace"))
	changed := normalized
	changed.Summary = counts{Passed: 1}
	require.False(t, reflect.DeepEqual(normalized, changed))
}

func TestOCIImageAndRuntimeIdentityDoNotConfusePlatformOrDigestKinds(t *testing.T) {
	platform := bib.Platform{Os: sys.OsLinux, Arch: sys.ArchAmd64, Edition: sys.EditionGeneric}
	raw := []byte(`[{"Id":"sha256:` + strings.Repeat("a", 64) + `","Os":"linux","Architecture":"amd64","Config":{"Entrypoint":["/bifroest"],"Cmd":["run"]}}]`)
	id, err := validateLoadedImage(raw, []string{"/bifroest"}, platform)
	require.NoError(t, err)
	require.Equal(t, "sha256:"+strings.Repeat("a", 64), id)
	_, err = validateLoadedImage(raw, []string{"/probe"}, platform)
	require.Error(t, err)
	require.NoError(t, validateRuntimePlatform([]byte(`{"Os":"linux","Arch":"amd64"}`), "docker", platform))
	require.NoError(t, validateRuntimePlatform([]byte(`{"host":{"os":"linux","arch":"x86_64"}}`), "podman", platform))
	require.Error(t, validateRuntimePlatform([]byte(`{"Os":"linux","Arch":"arm64"}`), "docker", platform))
	require.Error(t, validateRuntimePlatform([]byte(`null`), "docker", platform))
}

func TestJUnitPathNormalizationPreservesAssertionBodiesOtherThanLocations(t *testing.T) {
	raw := strings.ReplaceAll(sampleXML, "red_bftest.lua", "/host/workspace/red_bftest.lua")
	raw = strings.Replace(raw, "actual false", "actual /host/workspace/fact", 1)
	var document xmlReport
	require.NoError(t, xml.Unmarshal([]byte(raw), &document))
	normalized := normalizeXML(document, "/host/workspace")
	item := normalized.Suites[0].Cases[0]
	require.Equal(t, "/workspace/red_bftest.lua", item.File)
	require.Contains(t, item.Failures[0].Body, "/workspace/red_bftest.lua:7:")
	require.Contains(t, item.Failures[0].Body, "actual /host/workspace/fact")
}

func TestOCIWorkspaceIsPrivateReadOnlyAndContainsOnlyControlledFixtures(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	workspace := filepath.Join(t.TempDir(), "workspace")
	t.Cleanup(func() {
		_ = filepath.WalkDir(workspace, func(path string, entry os.DirEntry, err error) error {
			if err == nil {
				mode := os.FileMode(0600)
				if entry.IsDir() {
					mode = 0700
				}
				_ = os.Chmod(path, mode)
			}
			return err
		})
	})
	require.NoError(t, stageWorkspace(workspace))
	hashes, err := workspaceHashes(workspace)
	require.NoError(t, err)
	require.Contains(t, hashes, "pkg/test/examples/ssh/green-unix_bftest.lua")
	require.Contains(t, hashes, "_generated/invalid_bftest.lua")
	for path := range hashes {
		require.NotContains(t, path, ".env")
		info, err := os.Stat(filepath.Join(workspace, filepath.FromSlash(path)))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0444), info.Mode().Perm())
	}
}
