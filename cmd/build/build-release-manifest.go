// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	gos "os"
	"slices"
	"strings"
	"time"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

const releaseManifestFilename = "bifroest-release-manifest.json"

type buildReleaseManifest struct {
	*build
}

type releaseManifest struct {
	SchemaVersion int                      `json:"schemaVersion"`
	Project       string                   `json:"project"`
	Version       string                   `json:"version"`
	Revision      string                   `json:"revision"`
	Created       string                   `json:"created"`
	Registry      string                   `json:"registry"`
	ManifestAsset string                   `json:"manifestAsset"`
	ChecksumAsset string                   `json:"checksumAsset"`
	Assets        []releaseManifestAsset   `json:"assets"`
	Variants      []releaseManifestVariant `json:"variants"`
}

type releaseManifestAsset struct {
	Name      string `json:"name"`
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
}

type releaseManifestVariant struct {
	Os           string                       `json:"os"`
	Architecture string                       `json:"architecture"`
	Edition      string                       `json:"edition"`
	Archive      string                       `json:"archive,omitempty"`
	Notice       string                       `json:"notice,omitempty"`
	Sboms        releaseManifestVariantSboms  `json:"sboms"`
	Image        *releaseManifestVariantImage `json:"image,omitempty"`
}

type releaseManifestVariantSboms struct {
	Archive *releaseManifestSbomFiles `json:"archive,omitempty"`
	Image   *releaseManifestSbomFiles `json:"image,omitempty"`
}

type releaseManifestSbomFiles struct {
	Spdx      string `json:"spdx,omitempty"`
	CycloneDx string `json:"cycloneDx,omitempty"`
}

type releaseManifestVariantImage struct {
	Tag               string `json:"tag"`
	IndexReference    string `json:"indexReference"`
	IndexMediaType    string `json:"indexMediaType"`
	IndexDigest       string `json:"indexDigest"`
	Platform          string `json:"platform"`
	PlatformReference string `json:"platformReference"`
	PlatformMediaType string `json:"platformMediaType"`
	PlatformDigest    string `json:"platformDigest"`
}

type releaseManifestVariantBuilder struct {
	platform             *bib.Platform
	archive              string
	archiveDigest        string
	archiveSubjectName   string
	archiveMediaType     string
	archiveSubjectDigest string
	notice               string
	archiveSboms         releaseManifestSbomFiles
	imageSboms           releaseManifestSbomFiles
	imageMediaType       string
	imagePlatform        string
	imageDigest          string
}

type releaseManifestImageIndex struct {
	mediaType string
	digest    string
	platforms map[string]string
}

func newBuildReleaseManifest(b *build) *buildReleaseManifest {
	return &buildReleaseManifest{build: b}
}

func (this *buildReleaseManifest) create(_ context.Context, artifacts buildArtifacts, requireComplete bool) (_ buildArtifacts, rErr error) {
	if len(artifacts) == 0 {
		return artifacts, nil
	}
	builders := make(map[string]*releaseManifestVariantBuilder)
	indexes := make(map[sys.Edition]releaseManifestImageIndex)
	assets := make([]releaseManifestAsset, 0)
	assetNames := make(map[string]struct{})

	for _, artifact := range artifacts {
		switch artifact.t {
		case buildArtifactTypeArchive, buildArtifactTypeNotice, buildArtifactTypeSbom:
			digest, err := sha256File(artifact.filepath)
			if err != nil {
				return nil, fmt.Errorf("cannot hash release asset %s: %w", artifact.name(), err)
			}
			if _, exists := assetNames[artifact.name()]; exists {
				return nil, fmt.Errorf("duplicate release asset name %q", artifact.name())
			}
			assetNames[artifact.name()] = struct{}{}
			assets = append(assets, releaseManifestAsset{Name: artifact.name(), MediaType: artifact.mediaType(), Digest: digest})

			builder := releaseManifestBuilderFor(builders, artifact.Platform)
			switch artifact.t {
			case buildArtifactTypeArchive:
				if builder.archive != "" {
					return nil, fmt.Errorf("duplicate archive for %s", artifact.Platform)
				}
				builder.archive = artifact.name()
				builder.archiveDigest = digest
			case buildArtifactTypeNotice:
				if builder.notice != "" {
					return nil, fmt.Errorf("duplicate third-party notice for %s", artifact.Platform)
				}
				builder.notice = artifact.name()
			case buildArtifactTypeSbom:
				if artifact.sbom == nil {
					return nil, fmt.Errorf("SBOM artifact %s has no subject metadata", artifact.name())
				}
				if artifact.sbom.subjectName == "" || artifact.sbom.subjectMediaType == "" || artifact.sbom.subjectDigest == "" {
					return nil, fmt.Errorf("SBOM artifact %s has incomplete subject metadata", artifact.name())
				}
				var target *releaseManifestSbomFiles
				switch artifact.sbom.subjectType {
				case buildArtifactTypeArchive:
					target = &builder.archiveSboms
					if builder.archiveSubjectName != "" && builder.archiveSubjectName != artifact.sbom.subjectName {
						return nil, fmt.Errorf("archive SBOMs for %s have different subject names", artifact.Platform)
					}
					if builder.archiveMediaType != "" && builder.archiveMediaType != artifact.sbom.subjectMediaType {
						return nil, fmt.Errorf("archive SBOMs for %s have different subject media types", artifact.Platform)
					}
					if builder.archiveSubjectDigest != "" && builder.archiveSubjectDigest != artifact.sbom.subjectDigest {
						return nil, fmt.Errorf("archive SBOMs for %s have different subject digests", artifact.Platform)
					}
					builder.archiveSubjectName = artifact.sbom.subjectName
					builder.archiveMediaType = artifact.sbom.subjectMediaType
					builder.archiveSubjectDigest = artifact.sbom.subjectDigest
				case buildArtifactTypeImage:
					target = &builder.imageSboms
					if artifact.sbom.subjectPlatform == "" {
						return nil, fmt.Errorf("image SBOM artifact %s has no subject platform", artifact.name())
					}
					if builder.imageDigest != "" && builder.imageDigest != artifact.sbom.subjectDigest {
						return nil, fmt.Errorf("image SBOMs for %s have different subject digests", artifact.Platform)
					}
					if builder.imageMediaType != "" && builder.imageMediaType != artifact.sbom.subjectMediaType {
						return nil, fmt.Errorf("image SBOMs for %s have different subject media types", artifact.Platform)
					}
					if builder.imagePlatform != "" && builder.imagePlatform != artifact.sbom.subjectPlatform {
						return nil, fmt.Errorf("image SBOMs for %s have different subject platforms", artifact.Platform)
					}
					builder.imageMediaType = artifact.sbom.subjectMediaType
					builder.imagePlatform = artifact.sbom.subjectPlatform
					builder.imageDigest = artifact.sbom.subjectDigest
				default:
					return nil, fmt.Errorf("SBOM artifact %s has unsupported subject type %s", artifact.name(), artifact.sbom.subjectType)
				}
				if err := setReleaseManifestSbom(target, artifact.sbom.format, artifact.name()); err != nil {
					return nil, err
				}
			}
		case buildArtifactTypeImagePlatform:
			if artifact.ociIndex == nil {
				return nil, fmt.Errorf("image index for edition %s is empty", artifact.Edition)
			}
			digest, err := artifact.ociIndex.Digest()
			if err != nil {
				return nil, fmt.Errorf("cannot calculate image index digest for edition %s: %w", artifact.Edition, err)
			}
			if _, exists := indexes[artifact.Edition]; exists {
				return nil, fmt.Errorf("duplicate image index for edition %s", artifact.Edition)
			}
			mediaType, err := artifact.ociIndex.MediaType()
			if err != nil {
				return nil, fmt.Errorf("cannot identify image index media type for edition %s: %w", artifact.Edition, err)
			}
			indexManifest, err := artifact.ociIndex.IndexManifest()
			if err != nil {
				return nil, fmt.Errorf("cannot read image index for edition %s: %w", artifact.Edition, err)
			}
			platforms := make(map[string]string, len(indexManifest.Manifests))
			for _, descriptor := range indexManifest.Manifests {
				if descriptor.Platform == nil {
					return nil, fmt.Errorf("image index for edition %s contains a descriptor without platform", artifact.Edition)
				}
				platform := descriptor.Platform.OS + "/" + descriptor.Platform.Architecture
				if descriptor.Platform.Variant != "" {
					platform += "/" + descriptor.Platform.Variant
				}
				platforms[descriptor.Digest.String()] = platform
			}
			indexes[artifact.Edition] = releaseManifestImageIndex{mediaType: string(mediaType), digest: digest.String(), platforms: platforms}
		}
	}

	slices.SortFunc(assets, func(a, b releaseManifestAsset) int { return strings.Compare(a.Name, b.Name) })
	keys := make([]string, 0, len(builders))
	for key := range builders {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	variants := make([]releaseManifestVariant, 0, len(keys))
	usedImageDigests := make(map[sys.Edition]map[string]struct{})
	for _, key := range keys {
		builder := builders[key]
		if requireComplete && (builder.archive == "" || builder.notice == "") {
			return nil, fmt.Errorf("release variant %s has no archive or third-party notice", builder.platform)
		}
		if builder.archive != "" && builder.notice == "" {
			return nil, fmt.Errorf("archive for %s has no third-party notice", builder.platform)
		}
		archiveSbomsPresent := builder.archiveSboms.Spdx != "" || builder.archiveSboms.CycloneDx != ""
		if (requireComplete || archiveSbomsPresent) && (builder.archiveSboms.Spdx == "" || builder.archiveSboms.CycloneDx == "") {
			return nil, fmt.Errorf("archive for %s has incomplete SBOM formats", builder.platform)
		}
		if archiveSbomsPresent && builder.archive != builder.archiveSubjectName {
			return nil, fmt.Errorf("archive and SBOM subject name differ for %s", builder.platform)
		}
		if archiveSbomsPresent && builder.archiveMediaType != (&buildArtifact{t: buildArtifactTypeArchive, filepath: builder.archive}).mediaType() {
			return nil, fmt.Errorf("archive and SBOM subject media type differ for %s", builder.platform)
		}
		if archiveSbomsPresent && builder.archiveDigest != builder.archiveSubjectDigest {
			return nil, fmt.Errorf("archive digest and SBOM subject digest differ for %s", builder.platform)
		}
		imageSbomsPresent := builder.imageSboms.Spdx != "" || builder.imageSboms.CycloneDx != ""
		if (requireComplete && builder.platform.IsImageSupported() || imageSbomsPresent) && (builder.imageSboms.Spdx == "" || builder.imageSboms.CycloneDx == "") {
			return nil, fmt.Errorf("image for %s has incomplete SBOM formats", builder.platform)
		}
		variant := releaseManifestVariant{
			Os:           builder.platform.Os.String(),
			Architecture: builder.platform.Arch.String(),
			Edition:      builder.platform.Edition.String(),
			Archive:      builder.archive,
			Notice:       builder.notice,
		}
		if builder.archiveSboms.Spdx != "" || builder.archiveSboms.CycloneDx != "" {
			variant.Sboms.Archive = &builder.archiveSboms
		}
		if builder.imageSboms.Spdx != "" || builder.imageSboms.CycloneDx != "" {
			variant.Sboms.Image = &builder.imageSboms
			index, exists := indexes[builder.platform.Edition]
			if !exists {
				return nil, fmt.Errorf("image SBOM for %s has no matching image index", builder.platform)
			}
			if actualPlatform, exists := index.platforms[builder.imageDigest]; !exists {
				return nil, fmt.Errorf("image index for edition %s does not contain image digest %s", builder.platform.Edition, builder.imageDigest)
			} else if actualPlatform != builder.imagePlatform {
				return nil, fmt.Errorf("image index descriptor for %s identifies platform %s", builder.platform, actualPlatform)
			}
			used := usedImageDigests[builder.platform.Edition]
			if used == nil {
				used = make(map[string]struct{})
				usedImageDigests[builder.platform.Edition] = used
			}
			used[builder.imageDigest] = struct{}{}
			tag := releaseManifestImageTag(artifacts[0].version, builder.platform.Edition)
			registry := this.repo.fullImageName()
			variant.Image = &releaseManifestVariantImage{
				Tag:               registry + ":" + tag,
				IndexReference:    registry + "@" + index.digest,
				IndexMediaType:    index.mediaType,
				IndexDigest:       index.digest,
				Platform:          builder.imagePlatform,
				PlatformReference: registry + "@" + builder.imageDigest,
				PlatformMediaType: builder.imageMediaType,
				PlatformDigest:    builder.imageDigest,
			}
		}
		variants = append(variants, variant)
	}
	for edition, index := range indexes {
		if requireComplete && len(usedImageDigests[edition]) != len(index.platforms) {
			return nil, fmt.Errorf("image index for edition %s contains unreferenced platform images", edition)
		}
	}

	manifest := releaseManifest{
		SchemaVersion: 1,
		Project:       this.repo.String(),
		Version:       artifacts[0].version.String(),
		Revision:      artifacts[0].revision,
		Created:       artifacts[0].time.UTC().Format(time.RFC3339),
		Registry:      this.repo.fullImageName(),
		ManifestAsset: releaseManifestFilename,
		ChecksumAsset: "bifroest-checksums.txt",
		Assets:        assets,
		Variants:      variants,
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("cannot encode release manifest: %w", err)
	}
	raw = append(raw, '\n')
	result := &buildArtifact{
		Platform:     &bib.Platform{Testing: artifacts[0].Testing},
		buildContext: artifacts[0].buildContext,
		t:            buildArtifactTypeManifest,
		filepath:     artifacts[0].buildContext.filepath(releaseManifestFilename),
	}
	defer common.KeepCloseError(&rErr, result)
	if err := gos.WriteFile(result.filepath, raw, 0644); err != nil {
		return nil, fmt.Errorf("cannot write release manifest: %w", err)
	}
	return append(artifacts, result), nil
}

func releaseManifestBuilderFor(builders map[string]*releaseManifestVariantBuilder, platform *bib.Platform) *releaseManifestVariantBuilder {
	key := platform.FilenamePrefix("")
	result := builders[key]
	if result == nil {
		copy := *platform
		result = &releaseManifestVariantBuilder{platform: &copy}
		builders[key] = result
	}
	return result
}

func setReleaseManifestSbom(target *releaseManifestSbomFiles, format, name string) error {
	switch format {
	case "spdx-2.3":
		if target.Spdx != "" {
			return fmt.Errorf("duplicate SPDX SBOM for %s", name)
		}
		target.Spdx = name
	case "cyclonedx-1.6":
		if target.CycloneDx != "" {
			return fmt.Errorf("duplicate CycloneDX SBOM for %s", name)
		}
		target.CycloneDx = name
	default:
		return fmt.Errorf("unsupported SBOM format %q for %s", format, name)
	}
	return nil
}

func releaseManifestImageTag(version version, edition sys.Edition) string {
	value := version.String()
	if version.semver != nil {
		value = version.semver.String()
	}
	return edition.String() + "-" + value
}
