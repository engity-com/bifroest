package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	bib "github.com/engity-com/bifroest/internal/build"
)

var containerIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type containerInspection struct {
	// Podman expands cap-drop=ALL into individual names, and reports the
	// resulting sets separately. RawMessage distinguishes explicit null/empty
	// sets from Docker's absence of these fields.
	EffectiveCaps json.RawMessage
	BoundingCaps  json.RawMessage
	ID            string `json:"Id"`
	Image         string
	Config        struct {
		User, WorkingDir, Hostname string
		Entrypoint, Cmd, Env       []string
		Labels                     map[string]string
	}
	State struct {
		Running, OOMKilled bool
		ExitCode           int
		Error              string
	}
	HostConfig struct {
		NetworkMode                  string
		ReadonlyRootfs, Privileged   bool
		CapAdd, CapDrop, SecurityOpt []string
		PortBindings                 map[string]json.RawMessage
		Tmpfs                        map[string]string
		PidsLimit                    int64
		Memory                       int64
		NanoCpus                     int64
		CpuQuota, CpuPeriod          int64
	}
	Mounts []struct {
		Type, Source, Destination string
		RW                        bool
	}
}

func validateLoadedImage(raw []byte, entrypoint []string, platform bib.Platform) (string, error) {
	var records []struct {
		ID               string `json:"Id"`
		OS, Architecture string
		Config           struct{ Entrypoint, Cmd []string }
	}
	if err := json.Unmarshal(raw, &records); err != nil {
		return "", err
	}
	if len(records) != 1 || !containerIDPattern.MatchString(digestID(records[0].ID)) {
		return "", fmt.Errorf("runtime returned no unambiguous image identity")
	}
	image := records[0]
	if image.OS != platform.Os.String() || image.Architecture != platform.Arch.Oci() {
		return "", fmt.Errorf("loaded image platform differs from native Generic build")
	}
	if !reflect.DeepEqual(image.Config.Entrypoint, entrypoint) || !reflect.DeepEqual(image.Config.Cmd, []string{"run"}) {
		return "", fmt.Errorf("regular image entrypoint/default command changed")
	}
	return image.ID, nil
}

func digestID(value string) string { return strings.TrimPrefix(value, "sha256:") }

// A nonnil result establishes ownership only, so callers can clean up their own
// container even when its restrictions or process status subsequently fail.
func inspectContainer(raw []byte, token string, images ...string) (*containerInspection, error) {
	var records []containerInspection
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, err
	}
	if len(records) != 1 {
		return nil, fmt.Errorf("expected exactly one owned container")
	}
	result := records[0]
	imageMatches := false
	for _, image := range images {
		imageMatches = imageMatches || digestID(result.Image) == digestID(image)
	}
	if !containerIDPattern.MatchString(result.ID) || result.Config.Labels[ociRunLabel] != token || !imageMatches {
		return nil, fmt.Errorf("container identity/ownership differs; refusing cleanup of an unrelated container")
	}
	return &result, nil
}

func validateContainer(actual containerInspection, entrypoint, cli []string, workspace, reports, user string, exitCode int) error {
	if actual.Config.User != user || strings.HasPrefix(user, "0:") || actual.Config.WorkingDir != "/workspace" {
		return fmt.Errorf("container is not the expected non-root workspace process")
	}
	if !reflect.DeepEqual(actual.Config.Entrypoint, entrypoint) || !reflect.DeepEqual(actual.Config.Cmd, cli) {
		return fmt.Errorf("container did not use the regular image entrypoint and exact test arguments")
	}
	if actual.State.Running || actual.State.OOMKilled || actual.State.Error != "" || actual.State.ExitCode != exitCode {
		return fmt.Errorf("runtime/process state differs from the CLI exit status")
	}
	config := actual.HostConfig
	if config.NetworkMode != "none" || !config.ReadonlyRootfs || config.Privileged || len(config.CapAdd) != 0 || len(config.PortBindings) != 0 {
		return fmt.Errorf("container network/rootfs/privilege/port restrictions differ")
	}
	droppedAll := len(config.CapDrop) == 1 && strings.EqualFold(config.CapDrop[0], "ALL")
	emptySets := explicitlyEmptyCapabilities(actual.EffectiveCaps) && explicitlyEmptyCapabilities(actual.BoundingCaps)
	if !droppedAll && !emptySets {
		return fmt.Errorf("container did not drop every capability")
	}
	noPrivileges := false
	for _, option := range config.SecurityOpt {
		if option == "no-new-privileges" || option == "no-new-privileges=true" {
			noPrivileges = true
		}
	}
	if !noPrivileges {
		return fmt.Errorf("container lacks no-new-privileges")
	}
	oneCPU := config.NanoCpus == 1_000_000_000 || config.NanoCpus == 0 && config.CpuPeriod > 0 && config.CpuQuota == config.CpuPeriod
	if config.PidsLimit != 64 || config.Memory != 256<<20 || !oneCPU {
		return fmt.Errorf("container resource limits differ")
	}
	if len(config.Tmpfs) != 1 {
		return fmt.Errorf("unexpected writable tmpfs mounts")
	}
	tmpfs := config.Tmpfs["/tmp"]
	for _, option := range []string{"rw", "noexec", "nosuid", "nodev", "size=16m"} {
		found := false
		for _, actual := range strings.Split(tmpfs, ",") {
			found = found || actual == option || option == "size=16m" && (actual == "size=16777216" || actual == "size=16384k")
		}
		if !found {
			return fmt.Errorf("temporary storage lacks %q", option)
		}
	}
	seen := map[string]bool{}
	for _, mount := range actual.Mounts {
		// Some compatible runtimes also enumerate the already-checked tmpfs.
		if mount.Type == "tmpfs" && mount.Destination == "/tmp" {
			continue
		}
		if seen[mount.Destination] || mount.Type != "bind" {
			return fmt.Errorf("unexpected or duplicate mount")
		}
		seen[mount.Destination] = true
		switch mount.Destination {
		case "/workspace":
			if filepath.Clean(mount.Source) != filepath.Clean(workspace) || mount.RW {
				return fmt.Errorf("fixtures are not a read-only bind mount")
			}
		case "/reports":
			if filepath.Clean(mount.Source) != filepath.Clean(reports) || !mount.RW {
				return fmt.Errorf("reports are not the expected writable bind mount")
			}
		default:
			return fmt.Errorf("unexpected mount %q; sockets and host files are not allowed", mount.Destination)
		}
	}
	if len(seen) != 2 {
		return fmt.Errorf("fixture/report mount missing")
	}
	for _, entry := range actual.Config.Env {
		key, _, _ := strings.Cut(entry, "=")
		// Podman supplies fixed container identity metadata, not the host's HOME
		// or arbitrary caller environment. Match only these exact safe values.
		metadata := entry == "container=podman" || entry == "HOME=/workspace" || len(actual.ID) >= 12 && actual.Config.Hostname == actual.ID[:12] && entry == "HOSTNAME="+actual.Config.Hostname
		if key != "PATH" && entry != "TMPDIR=/tmp" && !metadata {
			return fmt.Errorf("unexpected container environment variable %q", key)
		}
	}
	return nil
}

func explicitlyEmptyCapabilities(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var values []string
	return json.Unmarshal(raw, &values) == nil && len(values) == 0
}

func validateRuntimePlatform(raw []byte, engine string, platform bib.Platform) error {
	var info struct {
		OS, Arch string
		Host     struct{ OS, Arch string }
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return err
	}
	if engine == "podman" {
		info.OS, info.Arch = info.Host.OS, info.Host.Arch
	}
	if info.Arch == "x86_64" {
		info.Arch = "amd64"
	}
	if info.Arch == "aarch64" {
		info.Arch = "arm64"
	}
	if info.OS != platform.Os.String() || info.Arch != platform.Arch.Oci() {
		return fmt.Errorf("runtime server platform %s/%s differs from native %s; emulated execution is not native parity", info.OS, info.Arch, platform.Oci())
	}
	return nil
}
