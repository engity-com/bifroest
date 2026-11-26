package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	gos "os"
	goexec "os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	log "github.com/echocat/slf4g"
	"gopkg.in/yaml.v3"
)

const (
	dependencyToolsPath = "mise.tools.yaml"
	dependencyMisePath  = "mise.toml"
	toolVersionPrefix   = "tool_version_"
)

var (
	toolVersionKeyPattern = regexp.MustCompile(`^tool_version_[a-z][a-z0-9_]*$`)
	toolVersionPattern    = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)*([-+][0-9A-Za-z.-]+)?$`)
)

type dependencyMiseCommand func(context.Context, string, ...string) ([]byte, error)

type dependencyToolCatalog struct {
	document yaml.Node
	versions map[string]*yaml.Node
}

func parseDependencyToolCatalog(raw []byte) (*dependencyToolCatalog, error) {
	result := &dependencyToolCatalog{versions: map[string]*yaml.Node{}}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&result.document); err != nil {
		return nil, fmt.Errorf("read %s: %w", dependencyToolsPath, err)
	}
	if err := decoder.Decode(new(yaml.Node)); err != io.EOF {
		return nil, fmt.Errorf("%s must contain exactly one YAML document", dependencyToolsPath)
	}
	if len(result.document.Content) != 1 || result.document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s must be a flat mapping of tool_version_* strings", dependencyToolsPath)
	}
	mapping := result.document.Content[0]
	for i := 0; i < len(mapping.Content); i += 2 {
		key, value := mapping.Content[i], mapping.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || !toolVersionKeyPattern.MatchString(key.Value) ||
			value.Kind != yaml.ScalarNode || value.Tag != "!!str" || !toolVersionPattern.MatchString(value.Value) ||
			key.Anchor != "" || value.Anchor != "" {
			return nil, fmt.Errorf("%s entry %q must be a tool_version_* key and a pinned version string", dependencyToolsPath, key.Value)
		}
		name := strings.TrimPrefix(key.Value, toolVersionPrefix)
		if _, exists := result.versions[name]; exists {
			return nil, fmt.Errorf("duplicate tool version %q", key.Value)
		}
		result.versions[name] = value
	}
	if len(result.versions) == 0 {
		return nil, fmt.Errorf("%s contains no tool versions", dependencyToolsPath)
	}
	return result, nil
}

func (this *dependencyToolCatalog) manifest(configuration []byte) ([]byte, map[string]string, error) {
	var source struct {
		Aliases map[string]string `toml:"tool_alias"`
	}
	if _, err := toml.Decode(string(configuration), &source); err != nil {
		return nil, nil, fmt.Errorf("read MISE tool aliases: %w", err)
	}
	tools := make(map[string]string, len(this.versions))
	for name, version := range this.versions {
		tools[name] = version.Value
	}
	var result bytes.Buffer
	err := toml.NewEncoder(&result).Encode(struct {
		Aliases map[string]string `toml:"tool_alias"`
		Tools   map[string]string `toml:"tools"`
	}{source.Aliases, tools})
	return result.Bytes(), source.Aliases, err
}

// MISE owns backend resolution and version precision. This command only checks
// metadata: unlike upgrade it does not install the proposed toolchain.
func runDependencyMise(ctx context.Context, directory string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	command := goexec.CommandContext(ctx, "mise", args...)
	command.Dir = directory
	// Do not inherit task-scoped version overrides or user/system configuration.
	// Retain authentication/proxy environment, but keep all MISE state temporary.
	for _, entry := range gos.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(strings.ToUpper(key), "MISE_") || key == "MISE_GITHUB_TOKEN" {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env,
		"MISE_CONFIG_DIR="+filepath.Join(directory, "config"),
		"MISE_GLOBAL_CONFIG_FILE="+filepath.Join(directory, "global.toml"),
		"MISE_SYSTEM_CONFIG_FILE="+filepath.Join(directory, "system.toml"),
		"MISE_CEILING_PATHS="+filepath.Dir(directory),
		"MISE_DATA_DIR="+filepath.Join(directory, "data"),
		"MISE_CACHE_DIR="+filepath.Join(directory, "cache"),
		"MISE_STATE_DIR="+filepath.Join(directory, "state"),
		"MISE_TRUSTED_CONFIG_PATHS="+directory,
		"MISE_AUTO_INSTALL=false",
		"MISE_YES=1",
	)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	result, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("mise %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return result, nil
}

func (this *dependencies) applyToolUpdates(ctx context.Context, files map[string][]byte) ([]dependencyCheck, error) {
	catalog, err := parseDependencyToolCatalog(files[dependencyToolsPath])
	if err != nil {
		return nil, err
	}
	manifest, aliases, err := catalog.manifest(files[dependencyMisePath])
	if err != nil {
		return nil, err
	}
	directory, err := gos.MkdirTemp("", "bifroest-mise-updates-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = gos.RemoveAll(directory) }()
	if err := gos.WriteFile(filepath.Join(directory, "mise.toml"), manifest, 0o600); err != nil {
		return nil, err
	}
	raw, err := this.miseCommand(ctx, directory, "outdated", "--bump", "--json")
	if err != nil {
		return nil, err
	}
	var resolved map[string]struct {
		Name      string  `json:"name"`
		Requested string  `json:"requested"`
		Bump      *string `json:"bump"`
		Latest    string  `json:"latest"`
	}
	if err := json.Unmarshal(raw, &resolved); err != nil {
		return nil, fmt.Errorf("decode MISE outdated results: %w", err)
	}
	if len(resolved) != len(catalog.versions) {
		return nil, fmt.Errorf("MISE returned %d tools, expected %d", len(resolved), len(catalog.versions))
	}
	names := make([]string, 0, len(catalog.versions))
	for name := range catalog.versions {
		names = append(names, name)
	}
	slices.Sort(names)
	checks := make([]dependencyCheck, 0, len(names))
	changed := false
	for _, name := range names {
		version := catalog.versions[name]
		result, exists := resolved[name]
		if !exists || result.Name != name || result.Requested != version.Value || !toolVersionPattern.MatchString(result.Latest) {
			return nil, fmt.Errorf("unexpected MISE result for %q", name)
		}
		current := version.Value
		if result.Bump != nil {
			current = *result.Bump
			if !toolVersionPattern.MatchString(current) {
				return nil, fmt.Errorf("invalid MISE bump for %q: %q", name, current)
			}
		}
		source := name
		if alias, exists := aliases[name]; exists {
			source = alias
		}
		check := dependencyCheck{
			name: "MISE " + name, source: source, previous: version.Value, current: current,
			files: []string{dependencyToolsPath}, changed: current != version.Value,
		}
		checks = append(checks, check)
		changed = changed || check.changed
		version.Value = current
	}
	if changed {
		var updated bytes.Buffer
		encoder := yaml.NewEncoder(&updated)
		encoder.SetIndent(2)
		if err := encoder.Encode(&catalog.document); err != nil {
			return nil, err
		}
		// Publish into the plan only after every result has passed validation.
		files[dependencyToolsPath] = updated.Bytes()
	}
	return checks, nil
}

func (this *dependencies) checkToolUpdates(ctx context.Context) error {
	files := map[string][]byte{}
	for _, path := range []string{dependencyToolsPath, dependencyMisePath} {
		raw, err := gos.ReadFile(path)
		if err != nil {
			return err
		}
		files[path] = raw
	}
	checks, err := this.applyToolUpdates(ctx, files)
	if err != nil {
		return err
	}
	for _, check := range checks {
		log.With("tool", check.name).With("previous", check.previous).With("resolved", check.current).With("changed", check.changed).Info("MISE tool update preview")
	}
	return nil
}
