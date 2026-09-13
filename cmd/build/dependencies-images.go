// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	dependencyCiWorkflowPath      = ".github/workflows/ci.yml"
	dependencyReleaseWorkflowPath = ".github/workflows/release.yml"
	dependencyBuildArchPath       = "internal/build/arch.go"
	dependencyBuildImagesPath     = "internal/build/images/build.go"
	dependencyE2eHarnessPath      = "test/e2e/harness_test.go"
)

type dependencyImageDigestResolver func(context.Context, string) (string, error)

type dependencyImageLocation struct {
	path       string
	references []string
	expected   int
}

type dependencyImageReference struct {
	start int
	end   int
	value string
}

type dependencyImage struct {
	name      string
	source    string
	locations []dependencyImageLocation
}

var dependencyImages = []dependencyImage{
	{
		name:   "Build environment image",
		source: "ghcr.io/engity-com/build-images/build:debian12",
		locations: []dependencyImageLocation{
			{path: dependencyCiWorkflowPath, references: []string{"ghcr.io/engity-com/build-images/go", "ghcr.io/engity-com/build-images/build:debian12"}, expected: 1},
			{path: dependencyReleaseWorkflowPath, references: []string{"ghcr.io/engity-com/build-images/go", "ghcr.io/engity-com/build-images/build:debian12"}, expected: 1},
		},
	},
	{
		name:   "Ubuntu 26.04 runtime base image",
		source: "docker.io/library/ubuntu:26.04",
		locations: []dependencyImageLocation{
			{path: dependencyBuildArchPath, references: []string{"docker.io/library/ubuntu:26.04"}, expected: 1},
		},
	},
	{
		name:   "Alpine runtime base image",
		source: "docker.io/library/alpine:latest",
		locations: []dependencyImageLocation{
			{path: dependencyBuildImagesPath, references: []string{"docker.io/library/alpine:latest"}, expected: 1},
			{path: dependencyE2eHarnessPath, references: []string{"docker.io/library/alpine", "docker.io/library/alpine:latest"}, expected: 1},
		},
	},
	{
		name:   "Windows Nano Server runtime base image",
		source: "mcr.microsoft.com/windows/nanoserver:ltsc2022",
		locations: []dependencyImageLocation{
			{path: dependencyBuildArchPath, references: []string{"mcr.microsoft.com/windows/nanoserver:ltsc2022"}, expected: 1},
			{path: dependencyBuildImagesPath, references: []string{"mcr.microsoft.com/windows/nanoserver:ltsc2022"}, expected: 1},
		},
	},
}

func resolveDependencyImageDigest(ctx context.Context, rawReference string) (string, error) {
	reference, err := name.ParseReference(rawReference, name.StrictValidation)
	if err != nil {
		return "", fmt.Errorf("cannot parse managed image reference %q: %w", rawReference, err)
	}
	descriptor, err := remote.Head(reference,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithUserAgent("bifroest-dependency-updater"),
	)
	if err != nil {
		return "", fmt.Errorf("cannot resolve managed image %s: %w", reference, err)
	}
	if descriptor.Digest.Algorithm != "sha256" || len(descriptor.Digest.Hex) != 64 {
		return "", fmt.Errorf("managed image %s resolved to unsupported digest %s", reference, descriptor.Digest)
	}
	return descriptor.Digest.String(), nil
}

func (this *dependencies) applyImageUpdates(ctx context.Context, files map[string][]byte) ([]dependencyCheck, error) {
	checks := make([]dependencyCheck, 0, len(dependencyImages))
	for _, image := range dependencyImages {
		digest, err := this.resolveImageDigest(ctx, image.source)
		if err != nil {
			return nil, err
		}
		target := image.source + "@" + digest
		previousSet := make(map[string]struct{})
		paths := make([]string, 0, len(image.locations))
		changed := false
		for _, location := range image.locations {
			content, exists := files[location.path]
			if !exists {
				return nil, fmt.Errorf("managed dependency file %q was not loaded", location.path)
			}
			matches := findDependencyImageReferences(content, location.references)
			if len(matches) != location.expected {
				return nil, fmt.Errorf("expected %d reference(s) for %s in %s, found %d", location.expected, image.source, location.path, len(matches))
			}
			for _, match := range matches {
				previousSet[match.value] = struct{}{}
				changed = changed || match.value != target
			}
			files[location.path] = replaceDependencyImageReferences(content, matches, target)
			paths = append(paths, location.path)
		}
		previous := make([]string, 0, len(previousSet))
		for value := range previousSet {
			previous = append(previous, value)
		}
		slices.Sort(previous)
		slices.Sort(paths)
		checks = append(checks, dependencyCheck{
			name:     image.name,
			source:   image.source,
			previous: strings.Join(previous, ", "),
			current:  target,
			files:    paths,
			changed:  changed,
		})
	}
	return checks, nil
}

func findDependencyImageReferences(content []byte, references []string) []dependencyImageReference {
	const digestPrefix = "@sha256:"
	const digestLength = 64

	var result []dependencyImageReference
	for _, reference := range references {
		marker := []byte(reference + digestPrefix)
		for offset := 0; offset < len(content); {
			relativeStart := bytes.Index(content[offset:], marker)
			if relativeStart < 0 {
				break
			}
			start := offset + relativeStart
			end := start + len(marker) + digestLength
			offset = start + 1
			if end > len(content) ||
				(start > 0 && isDependencyImageReferenceCharacter(content[start-1])) ||
				(end < len(content) && isDependencyImageReferenceCharacter(content[end])) ||
				!isLowerHex(content[end-digestLength:end]) {
				continue
			}
			result = append(result, dependencyImageReference{start: start, end: end, value: string(content[start:end])})
			offset = end
		}
	}
	slices.SortFunc(result, func(a, b dependencyImageReference) int {
		switch {
		case a.start < b.start:
			return -1
		case a.start > b.start:
			return 1
		default:
			return 0
		}
	})
	return result
}

func replaceDependencyImageReferences(content []byte, references []dependencyImageReference, target string) []byte {
	var result bytes.Buffer
	previousEnd := 0
	for _, reference := range references {
		_, _ = result.Write(content[previousEnd:reference.start])
		_, _ = result.WriteString(target)
		previousEnd = reference.end
	}
	_, _ = result.Write(content[previousEnd:])
	return result.Bytes()
}

func isDependencyImageReferenceCharacter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune("._:/@+-", rune(value))
}

func isLowerHex(value []byte) bool {
	for _, current := range value {
		if current < '0' || current > '9' {
			if current < 'a' || current > 'f' {
				return false
			}
		}
	}
	return true
}
