// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	gos "os"
	"path/filepath"
	"strings"
	"time"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/sys"
)

func (this *buildReleaseManifest) importPartial(ctx context.Context, artifacts buildArtifacts, filename string) (buildArtifacts, error) {
	fail := func(err error) (buildArtifacts, error) {
		return nil, fmt.Errorf("cannot import release manifest %q: %w", filename, err)
	}
	if err := requireRegularFile(filename); err != nil {
		return fail(err)
	}
	file, err := gos.Open(filename)
	if err != nil {
		return fail(err)
	}
	defer file.Close()

	var manifest releaseManifest
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return fail(fmt.Errorf("invalid JSON: %w", err))
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return fail(err)
	}

	buildContext, err := this.getBuildContext(ctx)
	if err != nil {
		return fail(err)
	}
	if err := this.validateImportedManifestContext(manifest, buildContext, filename); err != nil {
		return fail(err)
	}
	if len(manifest.Variants) != 1 {
		return fail(fmt.Errorf("expected exactly one variant, got %d", len(manifest.Variants)))
	}
	variant := manifest.Variants[0]
	var architecture sys.Arch
	if err := architecture.Set(variant.Architecture); err != nil || (architecture != sys.ArchAmd64 && architecture != sys.ArchArm64) ||
		variant.Os != sys.OsDarwin.String() || variant.Edition != sys.EditionExtended.String() {
		return fail(fmt.Errorf("expected supported Darwin extended variant, got %s/%s/%s", variant.Os, variant.Architecture, variant.Edition))
	}
	if variant.Image != nil || variant.Sboms.Image != nil {
		return fail(errors.New("darwin variant must not contain an image or image SBOMs"))
	}
	if variant.Archive == "" || variant.Notice == "" || variant.Sboms.Archive == nil ||
		variant.Sboms.Archive.Spdx == "" || variant.Sboms.Archive.CycloneDx == "" {
		return fail(errors.New("darwin variant has incomplete archive, notice, or archive SBOM references"))
	}

	platform := &bib.Platform{Os: sys.OsDarwin, Arch: architecture, Edition: sys.EditionExtended, Testing: artifactsTesting(artifacts)}
	references := []struct {
		name         string
		artifactType buildArtifactType
		format       string
		mediaType    string
	}{
		{variant.Archive, buildArtifactTypeArchive, "", "application/tar+gzip"},
		{variant.Notice, buildArtifactTypeNotice, "", "text/plain; charset=utf-8"},
		{variant.Sboms.Archive.Spdx, buildArtifactTypeSbom, "spdx-2.3", "application/spdx+json"},
		{variant.Sboms.Archive.CycloneDx, buildArtifactTypeSbom, "cyclonedx-1.6", "application/vnd.cyclonedx+json; version=1.6"},
	}
	referenceTypes := make(map[string]struct {
		artifactType buildArtifactType
		format       string
		mediaType    string
	}, len(references))
	for _, reference := range references {
		if err := validateReleaseAssetName(reference.name); err != nil {
			return fail(err)
		}
		if _, exists := referenceTypes[reference.name]; exists {
			return fail(fmt.Errorf("asset %q is referenced more than once", reference.name))
		}
		referenceTypes[reference.name] = struct {
			artifactType buildArtifactType
			format       string
			mediaType    string
		}{reference.artifactType, reference.format, reference.mediaType}
	}
	prefix := platform.FilenamePrefix(this.prefix)
	expectedArchive := prefix + ".tgz"
	expectedNotice := prefix + ".third-party-notices.txt"
	expectedReferences := []struct {
		actual   string
		expected string
	}{
		{variant.Archive, expectedArchive},
		{variant.Notice, expectedNotice},
		{variant.Sboms.Archive.Spdx, expectedArchive + ".spdx.json"},
		{variant.Sboms.Archive.CycloneDx, expectedArchive + ".cdx.json"},
	}
	for _, reference := range expectedReferences {
		if reference.actual != reference.expected {
			return fail(fmt.Errorf("unexpected Darwin release asset %q, expected %q", reference.actual, reference.expected))
		}
	}
	if len(manifest.Assets) != len(references) {
		return fail(fmt.Errorf("expected exactly four assets, got %d", len(manifest.Assets)))
	}

	localNames := make(map[string]struct{})
	for _, artifact := range artifacts {
		if artifact.filepath != "" {
			localNames[artifact.name()] = struct{}{}
		}
	}
	directory := filepath.Dir(filename)
	assetsByName := make(map[string]releaseManifestAsset, len(manifest.Assets))
	imported := make(buildArtifacts, 0, len(manifest.Assets))
	for _, asset := range manifest.Assets {
		if err := validateReleaseAssetName(asset.Name); err != nil {
			return fail(err)
		}
		if asset.Name == manifest.ManifestAsset || asset.Name == manifest.ChecksumAsset {
			return fail(fmt.Errorf("asset %q uses a reserved release filename", asset.Name))
		}
		if _, exists := assetsByName[asset.Name]; exists {
			return fail(fmt.Errorf("duplicate asset name %q", asset.Name))
		}
		if _, exists := localNames[asset.Name]; exists {
			return fail(fmt.Errorf("asset name %q duplicates a local artifact", asset.Name))
		}
		reference, exists := referenceTypes[asset.Name]
		if !exists {
			return fail(fmt.Errorf("asset %q is not referenced by the Darwin variant", asset.Name))
		}
		assetFilename := filepath.Join(directory, asset.Name)
		if err := requireRegularFile(assetFilename); err != nil {
			return fail(fmt.Errorf("invalid asset %q: %w", asset.Name, err))
		}
		artifact := &buildArtifact{
			Platform:     platform,
			buildContext: buildContext,
			t:            reference.artifactType,
			filepath:     assetFilename,
		}
		if artifact.mediaType() != reference.mediaType || asset.MediaType != reference.mediaType {
			return fail(fmt.Errorf("asset %q has unexpected media type %q", asset.Name, asset.MediaType))
		}
		digest, err := sha256File(assetFilename)
		if err != nil {
			return fail(fmt.Errorf("cannot hash asset %q: %w", asset.Name, err))
		}
		if asset.Digest != digest {
			return fail(fmt.Errorf("asset %q digest mismatch", asset.Name))
		}
		if reference.artifactType == buildArtifactTypeSbom {
			artifact.sbom = &buildArtifactSbom{
				format:           reference.format,
				subjectType:      buildArtifactTypeArchive,
				subjectName:      variant.Archive,
				subjectMediaType: references[0].mediaType,
				subjectDigest:    manifestAssetDigest(manifest.Assets, variant.Archive),
			}
		}
		assetsByName[asset.Name] = asset
		imported = append(imported, artifact)
	}
	if len(assetsByName) != len(referenceTypes) {
		return fail(errors.New("not every Darwin variant reference has a matching asset"))
	}

	checksumFilename := filepath.Join(directory, manifest.ChecksumAsset)
	if err := requireRegularFile(checksumFilename); err != nil {
		return fail(fmt.Errorf("invalid checksum asset: %w", err))
	}
	checksums, err := readReleaseChecksums(checksumFilename)
	if err != nil {
		return fail(err)
	}
	expectedChecksums := make(map[string]string, len(manifest.Assets)+1)
	manifestDigest, err := sha256File(filename)
	if err != nil {
		return fail(err)
	}
	expectedChecksums[manifest.ManifestAsset] = strings.TrimPrefix(manifestDigest, "sha256:")
	for _, asset := range manifest.Assets {
		expectedChecksums[asset.Name] = strings.TrimPrefix(asset.Digest, "sha256:")
	}
	if len(checksums) != len(expectedChecksums) {
		return fail(fmt.Errorf("checksum asset must cover exactly the four assets and partial manifest"))
	}
	for name, expected := range expectedChecksums {
		if actual, exists := checksums[name]; !exists || actual != expected {
			return fail(fmt.Errorf("checksum mismatch for %q", name))
		}
	}

	return append(artifacts, imported...), nil
}

func (this *buildReleaseManifest) validateImportedManifestContext(manifest releaseManifest, buildContext *buildContext, filename string) error {
	expected := releaseManifest{
		SchemaVersion: 1,
		Project:       this.repo.String(),
		Version:       buildContext.version.String(),
		Revision:      buildContext.revision,
		Created:       buildContext.time.UTC().Format(time.RFC3339),
		Registry:      this.repo.fullImageName(),
		ManifestAsset: releaseManifestFilename,
		ChecksumAsset: releaseChecksumFilename,
	}
	comparisons := []struct {
		name     string
		actual   any
		expected any
	}{
		{"schemaVersion", manifest.SchemaVersion, expected.SchemaVersion},
		{"project", manifest.Project, expected.Project},
		{"version", manifest.Version, expected.Version},
		{"revision", manifest.Revision, expected.Revision},
		{"created", manifest.Created, expected.Created},
		{"registry", manifest.Registry, expected.Registry},
		{"manifestAsset", manifest.ManifestAsset, expected.ManifestAsset},
		{"checksumAsset", manifest.ChecksumAsset, expected.ChecksumAsset},
	}
	for _, comparison := range comparisons {
		if comparison.actual != comparison.expected {
			return fmt.Errorf("%s mismatch: got %v, expected %v", comparison.name, comparison.actual, comparison.expected)
		}
	}
	if filepath.Base(filename) != manifest.ManifestAsset {
		return fmt.Errorf("manifest filename %q does not match manifestAsset %q", filepath.Base(filename), manifest.ManifestAsset)
	}
	return nil
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

func validateReleaseAssetName(name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return fmt.Errorf("release asset name %q is not a basename", name)
	}
	return nil
}

func requireRegularFile(filename string) error {
	info, err := gos.Lstat(filename)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", filename)
	}
	return nil
}

func readReleaseChecksums(filename string) (map[string]string, error) {
	file, err := gos.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return nil, fmt.Errorf("malformed checksum line %q", line)
		}
		digest, name := line[:64], line[66:]
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || strings.ToLower(digest) != digest {
			return nil, fmt.Errorf("malformed checksum digest for %q", name)
		}
		if err := validateReleaseAssetName(name); err != nil {
			return nil, err
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate checksum entry for %q", name)
		}
		result[name] = digest
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func manifestAssetDigest(assets []releaseManifestAsset, name string) string {
	for _, asset := range assets {
		if asset.Name == name {
			return asset.Digest
		}
	}
	return ""
}

func artifactsTesting(artifacts buildArtifacts) bool {
	if len(artifacts) > 0 && artifacts[0].Platform != nil {
		return artifacts[0].Testing
	}
	return false
}
