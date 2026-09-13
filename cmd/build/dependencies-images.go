// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"regexp"
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
	path     string
	pattern  *regexp.Regexp
	expected int
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
			{path: dependencyCiWorkflowPath, pattern: regexp.MustCompile(`ghcr\.io/engity-com/build-images/(?:go|build:debian12)@sha256:[0-9a-f]{64}`), expected: 1},
			{path: dependencyReleaseWorkflowPath, pattern: regexp.MustCompile(`ghcr\.io/engity-com/build-images/(?:go|build:debian12)@sha256:[0-9a-f]{64}`), expected: 1},
		},
	},
	{
		name:   "Ubuntu 26.04 runtime base image",
		source: "docker.io/library/ubuntu:26.04",
		locations: []dependencyImageLocation{
			{path: dependencyBuildArchPath, pattern: regexp.MustCompile(`docker\.io/library/ubuntu:26\.04@sha256:[0-9a-f]{64}`), expected: 1},
		},
	},
	{
		name:   "Alpine runtime base image",
		source: "docker.io/library/alpine:latest",
		locations: []dependencyImageLocation{
			{path: dependencyBuildImagesPath, pattern: regexp.MustCompile(`docker\.io/library/alpine:latest@sha256:[0-9a-f]{64}`), expected: 1},
			{path: dependencyE2eHarnessPath, pattern: regexp.MustCompile(`docker\.io/library/alpine(?::latest)?@sha256:[0-9a-f]{64}`), expected: 1},
		},
	},
	{
		name:   "Windows Nano Server runtime base image",
		source: "mcr.microsoft.com/windows/nanoserver:ltsc2022",
		locations: []dependencyImageLocation{
			{path: dependencyBuildArchPath, pattern: regexp.MustCompile(`mcr\.microsoft\.com/windows/nanoserver:ltsc2022@sha256:[0-9a-f]{64}`), expected: 1},
			{path: dependencyBuildImagesPath, pattern: regexp.MustCompile(`mcr\.microsoft\.com/windows/nanoserver:ltsc2022@sha256:[0-9a-f]{64}`), expected: 1},
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
			matches := location.pattern.FindAll(content, -1)
			if len(matches) != location.expected {
				return nil, fmt.Errorf("expected %d reference(s) for %s in %s, found %d", location.expected, image.source, location.path, len(matches))
			}
			for _, match := range matches {
				previous := string(match)
				previousSet[previous] = struct{}{}
				changed = changed || previous != target
			}
			files[location.path] = location.pattern.ReplaceAllLiteral(content, []byte(target))
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
