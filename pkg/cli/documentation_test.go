package cli

import (
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	clibase "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

type documentedCLICommand struct {
	path       []string
	profiles   map[string]bool
	executable bool
}

var cliAvailabilityCall = regexp.MustCompile(`(?s)<<\s*cli_availability\((.*?)\)\s*>>`)

func TestVisibleCLICommandsHaveMatchingDocumentation(t *testing.T) {
	app := NewApplication[clibase.NoOptions](nil, "", nil).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	commands := map[string]*documentedCLICommand{}
	profiles := map[string]bool{common.ProfileExecutable: true, common.ProfileRemote: true, common.ProfileManagement: true}
	collectVisibleCLICommands(t, app, nil, profiles, commands)
	require.NotEmpty(t, commands)
	root := filepath.Join("..", "..", "docs", "reference", "cli")
	defaults := documentedCLIAvailabilityDefaults(t)
	for name, command := range commands {
		t.Run(name, func(t *testing.T) {
			base := filepath.Join(append([]string{root}, command.path...)...)
			var pages []string
			for _, candidate := range []string{base + ".md", filepath.Join(base, "index.md")} {
				if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
					pages = append(pages, candidate)
				} else if err != nil && !os.IsNotExist(err) {
					require.NoError(t, err)
				}
			}
			require.Len(t, pages, 1, "visible command needs exactly one canonical documentation page at %s.md or %s/index.md", base, base)
			raw, err := os.ReadFile(pages[0])
			require.NoError(t, err)
			source := string(raw)
			require.Contains(t, source, "# `bifroest "+name+"`", "documentation title must identify its command")
			if !command.executable {
				require.Empty(t, cliAvailabilityCall.FindAllStringSubmatch(source, -1), "grouping commands must not advertise invocation modes")
				return
			}
			availability := documentedCLIAvailability(t, source, defaults)
			require.True(t, availability[runtime.GOOS], "command exists in this binary but documentation marks its platform unsupported")
			for field, profile := range map[string]string{
				"local": common.ProfileExecutable, "remote": common.ProfileRemote, "direct_ssh": common.ProfileManagement,
			} {
				require.Equal(t, command.profiles[profile], availability[field], "Invocation modes does not match the reachable %s variant", profile)
			}
		})
	}

	// Also catch stale pages that still advertise an executable command on this
	// platform after it was hidden, removed or made platform-specific.
	require.NoError(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		require.NoError(t, err)
		if relative == "help.md" { // A built-in flag, not a registered command.
			return nil
		}
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		if !cliAvailabilityCall.Match(raw) {
			return nil
		}
		availability := documentedCLIAvailability(t, string(raw), defaults)
		if !availability[runtime.GOOS] {
			return nil
		}
		name := strings.TrimSuffix(filepath.ToSlash(relative), ".md")
		name = strings.TrimSuffix(name, "/index")
		name = strings.ReplaceAll(name, "/", " ")
		require.Contains(t, commands, name, "documentation advertises a command missing from this platform's visible application: %s", relative)
		return nil
	}))
}

func collectVisibleCLICommands(t *testing.T, container clibase.Container, parent []string, allowed map[string]bool, result map[string]*documentedCLICommand) {
	t.Helper()
	for command := range container.Commands() {
		if !command.IsVisible() {
			continue
		}
		path := append(append([]string{}, parent...), command.Name())
		name := strings.Join(path, " ")
		definition := result[name]
		if definition == nil {
			definition = &documentedCLICommand{path: path, profiles: map[string]bool{}}
			result[name] = definition
		}
		effective := map[string]bool{}
		for _, profile := range command.Profiles() {
			require.True(t, allowed[profile], "visible %s variant is unreachable because a parent excludes profile %s", name, profile)
			effective[profile], definition.profiles[profile] = true, true
		}
		hasChildren := false
		for child := range command.Commands() {
			if child.IsVisible() {
				hasChildren = true
				break
			}
		}
		definition.executable = definition.executable || !hasChildren
		collectVisibleCLICommands(t, command, path, effective, result)
	}
}

func documentedCLIAvailabilityDefaults(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", ".theme", "marcos", "main.py"))
	require.NoError(t, err)
	signature := regexp.MustCompile(`(?s)def cli_availability\((.*?)\)\s*->\s*str:`).FindSubmatch(raw)
	require.Len(t, signature, 2, "availability macro signature is missing")
	defaults := map[string]bool{}
	for _, field := range regexp.MustCompile(`([a-z_]+)\s*:\s*bool\s*=\s*(True|False)`).FindAllStringSubmatch(string(signature[1]), -1) {
		defaults[field[1]] = field[2] == "True"
	}
	for _, field := range []string{"linux", "darwin", "windows", "local", "remote", "direct_ssh"} {
		_, exists := defaults[field]
		require.True(t, exists, "missing availability default for %s", field)
	}
	return defaults
}

func documentedCLIAvailability(t *testing.T, source string, defaults map[string]bool) map[string]bool {
	t.Helper()
	calls := cliAvailabilityCall.FindAllStringSubmatch(source, -1)
	require.Len(t, calls, 1, "executable command needs one Invocation modes declaration")
	actual := maps.Clone(defaults)
	argument := regexp.MustCompile(`^([a-z_]+)\s*=\s*(True|False)$`)
	for _, value := range strings.Split(calls[0][1], ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		field := argument.FindStringSubmatch(value)
		require.Len(t, field, 3, "availability must use literal named boolean arguments: %s", value)
		_, exists := actual[field[1]]
		require.True(t, exists, "unknown availability field %s", field[1])
		actual[field[1]] = field[2] == "True"
	}
	return actual
}
