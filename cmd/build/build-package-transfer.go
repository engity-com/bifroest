package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	gos "os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/layout"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/sys"
)

const preparedPackagesFilename = "prepared-packages.json"
const preparedImagesDirectory = "prepared-images"

// This is a same-run CI handoff, not a public release artifact format.
type preparedPackages struct {
	SchemaVersion int                       `json:"schemaVersion"`
	Project       string                    `json:"project"`
	Version       string                    `json:"version"`
	Revision      string                    `json:"revision"`
	Vendor        string                    `json:"vendor"`
	BuildTime     time.Time                 `json:"buildTime"`
	Stages        buildStages               `json:"stages"`
	Platforms     []string                  `json:"platforms"`
	Files         map[string]string         `json:"files"`
	Artifacts     []preparedPackageArtifact `json:"artifacts"`
}

type preparedPackageArtifact struct {
	Type     buildArtifactType       `json:"type"`
	Platform preparedPackagePlatform `json:"platform"`
	Filename string                  `json:"filename,omitempty"`
	Digest   string                  `json:"digest,omitempty"`
}

type preparedPackagePlatform struct {
	Os      sys.Os      `json:"os,omitempty"`
	Arch    sys.Arch    `json:"arch,omitempty"`
	Edition sys.Edition `json:"edition,omitempty"`
	Testing bool        `json:"testing,omitempty"`
}

func (p preparedPackagePlatform) String() string { return bib.Platform(p).String() }

func (this *build) preparedPackageContext(ctx context.Context) (preparedPackages, error) {
	bc, err := this.getBuildContext(ctx)
	if err != nil {
		return preparedPackages{}, err
	}
	stages, err := this.stages(ctx)
	if err != nil {
		return preparedPackages{}, err
	}
	result := preparedPackages{
		SchemaVersion: 1, Project: this.repo.String(), Version: bc.version.String(),
		Revision: bc.revision, Vendor: bc.vendor, BuildTime: bc.time,
		Stages: slices.Clone(stages),
	}
	for p := range this.distributablePlatforms(this.testing) {
		result.Platforms = append(result.Platforms, p.String())
	}
	slices.Sort(result.Platforms)
	return result, nil
}

func (this *build) savePreparedPackages(ctx context.Context, artifacts buildArtifacts) error {
	plan, err := this.preparedPackageContext(ctx)
	if err != nil {
		return err
	}
	filename := filepath.Join(this.dest, preparedPackagesFilename)
	if _, err := gos.Lstat(filename); !gos.IsNotExist(err) {
		return fmt.Errorf("prepared package handoff already exists or cannot be inspected: %v", err)
	}
	for _, artifact := range artifacts {
		if !artifact.t.canBePublished() && artifact.t != buildArtifactTypeImagePlatform {
			continue
		}
		entry := preparedPackageArtifact{Type: artifact.t, Platform: preparedPackagePlatform(*artifact.Platform)}
		if artifact.t == buildArtifactTypeImagePlatform {
			digest, err := artifact.ociIndex.Digest()
			if err != nil {
				return err
			}
			entry.Digest = digest.String()
			// Persist the exact merged index, including its chart descriptor and blobs.
			directory := filepath.Join(this.dest, preparedImagesDirectory, artifact.Edition.String())
			if _, err := layout.Write(directory, artifact.ociIndex); err != nil {
				return fmt.Errorf("cannot save prepared image: %w", err)
			}
		} else {
			entry.Filename = artifact.name()
			if filepath.Clean(artifact.filepath) != filepath.Clean(filepath.Join(this.dest, plan.Version, entry.Filename)) {
				return fmt.Errorf("prepared artifact is outside the package directory: %s", artifact.filepath)
			}
		}
		plan.Artifacts = append(plan.Artifacts, entry)
	}
	if err := this.validatePreparedPackageArtifacts(plan); err != nil {
		return err
	}
	plan.Files, err = packageTransferFiles(this.dest)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	if err := gos.WriteFile(filename, append(raw, '\n'), 0644); err != nil {
		return err
	}
	if this.optionsOutputFilename != "" {
		file, err := gos.OpenFile(this.optionsOutputFilename, gos.O_CREATE|gos.O_WRONLY|gos.O_APPEND, 0644)
		if err != nil {
			return err
		}
		_, writeErr := fmt.Fprintf(file, "publish=%t\n", plan.Stages.contains(buildStagePublish))
		return errors.Join(writeErr, file.Close())
	}
	return nil
}

func (this *build) loadPreparedPackages(ctx context.Context) (buildArtifacts, error) {
	expected, err := this.preparedPackageContext(ctx)
	if err != nil {
		return nil, err
	}
	files, err := packageTransferFiles(this.dest)
	if err != nil {
		return nil, err
	}
	raw, err := gos.ReadFile(filepath.Join(this.dest, preparedPackagesFilename))
	if err != nil {
		return nil, err
	}
	var plan preparedPackages
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("prepared package handoff has trailing data")
	}
	if plan.SchemaVersion != expected.SchemaVersion || plan.Project != expected.Project ||
		plan.Version != expected.Version || plan.Revision != expected.Revision || plan.Vendor != expected.Vendor ||
		!plan.BuildTime.Equal(expected.BuildTime) || !slices.Equal(plan.Stages, expected.Stages) ||
		!slices.Equal(plan.Platforms, expected.Platforms) {
		return nil, fmt.Errorf("prepared packages do not match the expected build")
	}
	if !maps.Equal(files, plan.Files) {
		return nil, fmt.Errorf("prepared package files are missing, unexpected or have changed digests")
	}
	if err := this.validatePreparedPackageArtifacts(plan); err != nil {
		return nil, err
	}
	bc, err := this.getBuildContext(ctx)
	if err != nil {
		return nil, err
	}
	var result buildArtifacts
	for _, entry := range plan.Artifacts {
		platform := bib.Platform(entry.Platform)
		a := &buildArtifact{Platform: &platform, buildContext: bc, t: entry.Type}
		if entry.Type == buildArtifactTypeImagePlatform {
			path, err := layout.FromPath(filepath.Join(this.dest, preparedImagesDirectory, entry.Platform.Edition.String()))
			if err != nil {
				return nil, err
			}
			a.ociIndex, err = path.ImageIndex()
			if err != nil {
				return nil, err
			}
			digest, err := a.ociIndex.Digest()
			if err != nil || digest.String() != entry.Digest {
				return nil, fmt.Errorf("prepared image index digest does not match: %v", err)
			}
		} else {
			if _, exists := plan.Files[filepath.ToSlash(filepath.Join(plan.Version, entry.Filename))]; !exists {
				return nil, fmt.Errorf("prepared artifact %s has no file digest", entry.Filename)
			}
			a.filepath = bc.filepath(entry.Filename)
		}
		result = append(result, a)
	}
	return result, nil
}

func (this *build) publishPreparedPackages(ctx context.Context) error {
	artifacts, err := this.loadPreparedPackages(ctx)
	if err != nil {
		return err
	}
	stages, err := this.stages(ctx)
	if err != nil {
		return err
	}
	if stages.contains(buildStagePublish) {
		return this.publish(ctx, artifacts)
	}
	return nil
}

func (this *build) validatePreparedPackageArtifacts(plan preparedPackages) error {
	seen := make(map[string]bool)
	archives := make(map[string]bool)
	images := make(map[sys.Edition]bool)
	fileEntries := make(map[string]preparedPackageArtifact)
	for _, entry := range plan.Artifacts {
		key := entry.Filename
		if entry.Type == buildArtifactTypeImagePlatform {
			if !slices.Contains(sys.AllEditionVariants(), entry.Platform.Edition) || entry.Digest == "" || entry.Filename != "" {
				return fmt.Errorf("invalid prepared image index")
			}
			key = "image/" + entry.Platform.Edition.String()
			images[entry.Platform.Edition] = true
		} else if !entry.Type.canBePublished() || entry.Filename == "" || filepath.Base(entry.Filename) != entry.Filename || !filepath.IsLocal(entry.Filename) {
			return fmt.Errorf("invalid prepared package artifact %q", entry.Filename)
		} else {
			fileEntries[entry.Filename] = entry
		}
		if seen[key] {
			return fmt.Errorf("duplicate prepared package artifact %s", key)
		}
		seen[key] = true
		if entry.Type == buildArtifactTypeArchive {
			if archives[entry.Platform.String()] {
				return fmt.Errorf("duplicate prepared archive for %s", entry.Platform)
			}
			archives[entry.Platform.String()] = true
		}
	}
	for p := range this.distributablePlatforms(this.testing) {
		if plan.Stages.contains(buildStageArchive) && !archives[p.String()] {
			return fmt.Errorf("missing prepared archive for %s", p)
		}
		if plan.Stages.contains(buildStageImage) && p.IsImageSupported() && !images[p.Edition] {
			return fmt.Errorf("missing prepared image index for %s", p.Edition)
		}
	}
	if plan.Stages.contains(buildStageDigest) && (!seen[releaseManifestFilename] || !seen["bifroest-checksums.txt"]) {
		return fmt.Errorf("missing prepared release manifest or checksums")
	}
	if plan.Stages.contains(buildStageDigest) {
		if err := this.validatePreparedPackageManifest(plan, fileEntries); err != nil {
			return err
		}
	}
	if len(plan.Artifacts) == 0 {
		return fmt.Errorf("prepared package handoff has no artifacts")
	}
	return nil
}

func (this *build) validatePreparedPackageManifest(plan preparedPackages, entries map[string]preparedPackageArtifact) error {
	directory := filepath.Join(this.dest, plan.Version)
	raw, err := gos.ReadFile(filepath.Join(directory, releaseManifestFilename))
	if err != nil {
		return err
	}
	var manifest releaseManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	if manifest.Project != plan.Project || manifest.Version != plan.Version || manifest.Revision != plan.Revision ||
		manifest.Created != plan.BuildTime.UTC().Format(time.RFC3339) || manifest.Registry != this.repo.fullImageName() ||
		manifest.ManifestAsset != releaseManifestFilename || manifest.ChecksumAsset != "bifroest-checksums.txt" ||
		len(entries) != len(manifest.Assets)+2 {
		return fmt.Errorf("prepared artifacts do not match the release manifest")
	}
	for _, asset := range manifest.Assets {
		entry, found := entries[asset.Name]
		if !found || (&buildArtifact{t: entry.Type, filepath: entry.Filename}).mediaType() != asset.MediaType {
			return fmt.Errorf("missing or invalid prepared release asset %s", asset.Name)
		}
		digest, err := sha256File(filepath.Join(directory, entry.Filename))
		if err != nil || digest != asset.Digest {
			return fmt.Errorf("prepared release asset digest does not match: %s: %v", asset.Name, err)
		}
	}
	var checksums strings.Builder
	names := make([]string, 0, len(entries))
	for name := range entries {
		if name != "bifroest-checksums.txt" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		digest, err := sha256File(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		fmt.Fprintf(&checksums, "%s  %s\n", strings.TrimPrefix(digest, "sha256:"), name)
	}
	raw, err = gos.ReadFile(filepath.Join(directory, "bifroest-checksums.txt"))
	if err != nil || string(raw) != checksums.String() {
		return fmt.Errorf("prepared release checksums do not match: %v", err)
	}
	return nil
}

func packageTransferFiles(directory string) (map[string]string, error) {
	result := make(map[string]string)
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("package handoff contains a non-regular file: %s", path)
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		if name == preparedPackagesFilename {
			return nil
		}
		result[filepath.ToSlash(name)], err = sha256File(path)
		return err
	})
	return result, err
}
