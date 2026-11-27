// Package bifroest exposes repository build metadata shared by build tools.
package bifroest

import (
	_ "embed"
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"
)

// Embed the canonical catalog so validation also works in packaged binaries,
// without looking for a source checkout at runtime.
//
//go:embed mise.tools.yaml
var toolVersionsYAML []byte

var toolVersions = sync.OnceValue(func() map[string]string {
	var versions map[string]string
	if err := yaml.Unmarshal(toolVersionsYAML, &versions); err != nil {
		panic(fmt.Errorf("invalid embedded tool catalog: %w", err))
	}
	return versions
})

// ToolVersion returns an exact version from the source checkout's tool catalog.
// An unknown name is a programming/configuration error, not an ambient fallback.
func ToolVersion(name string) string {
	version := toolVersions()["tool_version_"+name]
	if version == "" {
		panic(fmt.Errorf("missing tool version %q in embedded catalog", name))
	}
	return version
}
