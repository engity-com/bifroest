package test

import (
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// Platform describes the binary under test, not a suite's modeled environment.
// Embedders may supply these values explicitly. Empty OS/Arch use the running
// Go binary's platform; an empty Version means that no version was supplied.
// The CLI supplies its own build metadata and exposes no override flags.
type Platform struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Version string `json:"version,omitempty"`
}

func (this Platform) resolved() Platform {
	if this.OS == "" {
		this.OS = runtime.GOOS
	}
	if this.Arch == "" {
		this.Arch = runtime.GOARCH
	}
	return this
}

type platformSpec struct {
	os, arch []string
	versions []versionSelector
}

func (this platformSpec) matches(binary Platform) (bool, string, error) {
	if this.os != nil && !matchesOS(this.os, binary.OS) {
		return false, "os does not match platform", nil
	}
	if this.arch != nil && !slices.Contains(this.arch, binary.Arch) {
		return false, "arch does not match platform", nil
	}
	if this.versions == nil {
		return true, "", nil
	}
	if len(this.versions) == 0 {
		return false, "version does not match platform", nil
	}
	if binary.Version == "" {
		return false, "", invalid("binary version is required by the platform selector")
	}
	parsed := parseSemver(binary.Version)
	for _, selector := range this.versions {
		if selector.matches(binary.Version, parsed) {
			return true, "", nil
		}
	}
	return false, "version does not match platform", nil
}

func matchesOS(selectors []string, actual string) bool {
	for _, selector := range selectors {
		switch selector {
		case "unix":
			if actual == "linux" || actual == "darwin" {
				return true
			}
		case actual:
			return true
		}
	}
	return false
}

var versionPrefix = regexp.MustCompile(`^(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$`)
var platformToken = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

type versionSelector struct {
	literal                        string
	exact, lower, upper            *semver.Version
	prefix                         []uint64
	lowerInclusive, upperInclusive bool
}

// Bifroest release builds use v-prefixed versions. Recognize that convention
// only for complete, otherwise strict SemVer values; opaque labels are exact,
// case-sensitive strings and are never coerced or normalized.
func parseSemver(value string) *semver.Version {
	parsed, err := semver.StrictNewVersion(strings.TrimPrefix(value, "v"))
	if err != nil {
		return nil
	}
	return parsed
}

func parseVersionSelector(value string) (versionSelector, error) {
	var result versionSelector
	if strings.HasPrefix(value, "[") || strings.HasPrefix(value, "(") {
		if len(value) < 3 || (value[len(value)-1] != ']' && value[len(value)-1] != ')') {
			return result, invalid("invalid platform version interval")
		}
		bounds := strings.Split(value[1:len(value)-1], ",")
		if len(bounds) != 2 {
			return result, invalid("platform version intervals require two bounds")
		}
		lower, upper := strings.TrimSpace(bounds[0]), strings.TrimSpace(bounds[1])
		result.lowerInclusive, result.upperInclusive = value[0] == '[', value[len(value)-1] == ']'
		if lower == "" && upper == "" || lower == "" && result.lowerInclusive || upper == "" && result.upperInclusive {
			return result, invalid("invalid unbounded platform version interval")
		}
		if lower != "" {
			result.lower = parseSemver(lower)
			if result.lower == nil {
				return result, invalid("platform version bounds require complete SemVer values")
			}
		}
		if upper != "" {
			result.upper = parseSemver(upper)
			if result.upper == nil {
				return result, invalid("platform version bounds require complete SemVer values")
			}
		}
		if result.lower != nil && result.upper != nil {
			order := result.lower.Compare(result.upper)
			if order > 0 || order == 0 && (!result.lowerInclusive || !result.upperInclusive) {
				return result, invalid("empty or reversed platform version interval")
			}
		}
		return result, nil
	}
	if parts := versionPrefix.FindStringSubmatch(value); parts != nil {
		for _, part := range parts[1:] {
			if part == "" {
				break
			}
			number, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return result, invalid("platform version prefix exceeds integer limits")
			}
			result.prefix = append(result.prefix, number)
		}
	} else if parsed := parseSemver(value); parsed != nil {
		result.exact = parsed
	} else {
		result.literal = value
	}
	return result, nil
}

func (this versionSelector) matches(raw string, parsed *semver.Version) bool {
	if this.literal != "" {
		return this.literal == raw
	}
	if parsed == nil {
		return false
	}
	if this.exact != nil {
		return this.exact.Equal(parsed)
	}
	if this.prefix != nil {
		return parsed.Prerelease() == "" && parsed.Major() == this.prefix[0] && (len(this.prefix) == 1 || parsed.Minor() == this.prefix[1])
	}
	if parsed.Prerelease() != "" && (this.lower == nil || this.lower.Prerelease() == "") && (this.upper == nil || this.upper.Prerelease() == "") {
		return false
	}
	if this.lower != nil {
		order := parsed.Compare(this.lower)
		if order < 0 || order == 0 && !this.lowerInclusive {
			return false
		}
	}
	if this.upper != nil {
		order := parsed.Compare(this.upper)
		if order > 0 || order == 0 && !this.upperInclusive {
			return false
		}
	}
	return true
}
