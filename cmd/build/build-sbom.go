package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	gos "os"
	osexec "os/exec"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/uuid"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/common"
)

const (
	syftConfigurationFile = ".syft.yaml"
	syftVersion           = "1.51.1"
)

func newBuildSbom(b *build) *buildSbom {
	return &buildSbom{build: b}
}

type buildSbom struct {
	*build
}

type buildArtifactSbom struct {
	format           string
	subjectType      buildArtifactType
	subjectName      string
	subjectMediaType string
	subjectPlatform  string
	subjectDigest    string
}

func (this *buildSbom) attach(_ *kingpin.CmdClause) {}

func (this *buildSbom) create(ctx context.Context, artifacts buildArtifacts) (_ buildArtifacts, rErr error) {
	result := append(buildArtifacts(nil), artifacts...)
	for _, artifact := range append(buildArtifacts(nil), artifacts...) {
		if artifact.t != buildArtifactTypeArchive && artifact.t != buildArtifactTypeImage {
			continue
		}
		created, err := this.createForArtifact(ctx, artifact)
		if err != nil {
			return nil, err
		}
		result = append(result, created...)
	}
	return result, nil
}

func (this *buildSbom) createForArtifact(ctx context.Context, source *buildArtifact) (_ buildArtifacts, rErr error) {
	if source.thirdPartyLicenseInventory == nil {
		return nil, fmt.Errorf("SBOM source %v has no third-party license inventory", source)
	}
	sourceReference, sourceName, subjectDigest, cleanup, err := this.sourceFor(source)
	if err != nil {
		return nil, err
	}
	defer common.KeepError(&rErr, cleanup)
	subjectMediaType := source.mediaType()
	subjectPlatform := ""
	if source.t == buildArtifactTypeImage {
		mediaType, err := source.ociImage.MediaType()
		if err != nil {
			return nil, fmt.Errorf("cannot identify media type of SBOM source %v: %w", source, err)
		}
		subjectMediaType = string(mediaType)
		config, err := source.ociImage.ConfigFile()
		if err != nil {
			return nil, fmt.Errorf("cannot identify platform of SBOM source %v: %w", source, err)
		}
		subjectPlatform = config.OS + "/" + config.Architecture
		if config.Variant != "" {
			subjectPlatform += "/" + config.Variant
		}
	}

	outputs := []struct {
		format string
		name   string
		suffix string
	}{
		{format: "spdx-json@2.3", name: "spdx-2.3", suffix: ".spdx.json"},
		{format: "cyclonedx-json@1.6", name: "cyclonedx-1.6", suffix: ".cdx.json"},
	}
	result := make(buildArtifacts, 0, len(outputs))
	args := []string{
		"scan",
		"--config", syftConfigurationFile,
		"--source-name", sourceName,
		"--source-version", source.version.String(),
	}
	if source.t == buildArtifactTypeImage {
		args = append(args, "--platform", source.Os.String()+"/"+source.Arch.Oci())
	}
	args = append(args, sourceReference)
	for _, output := range outputs {
		artifact, err := this.newBuildFileArtifact(ctx, source.Platform, buildArtifactTypeSbom, sourceName+output.suffix)
		if err != nil {
			return nil, err
		}
		artifact.sbom = &buildArtifactSbom{
			format:           output.name,
			subjectType:      source.t,
			subjectName:      sourceName,
			subjectMediaType: subjectMediaType,
			subjectPlatform:  subjectPlatform,
			subjectDigest:    subjectDigest,
		}
		result = append(result, artifact)
		args = append(args, "-o", output.format+"="+artifact.filepath)
	}

	l := log.With("artifact", source).With("stage", buildStageSbom)
	start := time.Now()
	l.Debug("building SBOMs...")
	executable, err := verifiedGoTool("syft", "github.com/anchore/syft", "v"+syftVersion)
	if err != nil {
		return nil, err
	}
	cmd := osexec.CommandContext(ctx, executable, args...)
	cmd.Env = append(gos.Environ(), "SYFT_CHECK_FOR_APP_UPDATE=false")
	cmd.Stdout = gos.Stdout
	cmd.Stderr = gos.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cannot create SBOMs for %v: %w", source, err)
	}
	for _, artifact := range result {
		if err := normalizeSbom(artifact.filepath, *source.Platform, source.t, sourceName, subjectDigest, source.time, source.thirdPartyLicenseInventory); err != nil {
			return nil, err
		}
	}
	l.With("duration", time.Since(start).Truncate(time.Millisecond)).Info("SBOMs built")
	return result, nil
}

func (this *buildSbom) sourceFor(artifact *buildArtifact) (reference, name, digest string, cleanup func() error, rErr error) {
	cleanup = func() error { return nil }
	if artifact.t == buildArtifactTypeArchive {
		digest, rErr = sha256File(artifact.filepath)
		return artifact.filepath, artifact.name(), digest, cleanup, rErr
	}
	if artifact.t != buildArtifactTypeImage || artifact.ociImage == nil {
		return "", "", "", cleanup, fmt.Errorf("cannot create SBOM source for %v", artifact)
	}
	directory, err := gos.MkdirTemp("", "bifroest-sbom-image-*")
	if err != nil {
		return "", "", "", cleanup, err
	}
	success := false
	defer func() {
		if !success {
			_ = gos.RemoveAll(directory)
		}
	}()
	cleanup = func() error { return gos.RemoveAll(directory) }
	layoutPath, err := layout.Write(directory, empty.Index)
	if err != nil {
		return "", "", "", cleanup, err
	}
	configuration, err := artifact.ociImage.ConfigFile()
	if err != nil {
		return "", "", "", cleanup, err
	}
	if err := layoutPath.AppendImage(artifact.ociImage, layout.WithPlatform(*configuration.Platform())); err != nil {
		return "", "", "", cleanup, err
	}
	hash, err := artifact.ociImage.Digest()
	if err != nil {
		return "", "", "", cleanup, err
	}
	name = artifact.Platform.FilenamePrefix(this.prefix + "-image")
	success = true
	return "oci-dir:" + directory, name, hash.String(), cleanup, nil
}

func sha256File(filename string) (string, error) {
	file, err := gos.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func normalizeSbom(filename string, platform bib.Platform, artifactType buildArtifactType, subjectName, subjectDigest string, timestamp time.Time, licenseInventory ...*thirdPartyLicenseInventory) error {
	raw, err := gos.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("cannot read generated SBOM %q: %w", filename, err)
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("cannot parse generated SBOM %q: %w", filename, err)
	}
	format := ""
	formattedTime := timestamp.UTC().Format(time.RFC3339)
	if strings.HasSuffix(filename, ".spdx.json") {
		format = "spdx-json@2.3"
		creationInfo, ok := document["creationInfo"].(map[string]any)
		if !ok {
			return fmt.Errorf("generated SPDX SBOM %q has no creationInfo", filename)
		}
		creationInfo["created"] = formattedTime
		packages, ok := document["packages"].([]any)
		if !ok {
			return fmt.Errorf("generated SPDX SBOM %q has no packages", filename)
		}
		rootFound := false
		for _, rawPackage := range packages {
			pkg, ok := rawPackage.(map[string]any)
			if !ok || pkg["name"] != subjectName {
				continue
			}
			rootFound = true
			references, _ := pkg["externalRefs"].([]any)
			platformReference := platform.Os.String() + "/" + platform.Arch.Oci()
			platformReferenceExists := false
			for _, rawReference := range references {
				reference, ok := rawReference.(map[string]any)
				if ok && reference["referenceType"] == "bifroest-platform" && reference["referenceLocator"] == platformReference {
					platformReferenceExists = true
				}
			}
			if !platformReferenceExists {
				references = append(references, map[string]any{
					"referenceCategory": "OTHER",
					"referenceType":     "bifroest-platform",
					"referenceLocator":  platformReference,
				})
			}
			if artifactType == buildArtifactTypeImage {
				purlUpdated := false
				for _, rawReference := range references {
					reference, ok := rawReference.(map[string]any)
					if !ok || reference["referenceType"] != "purl" {
						continue
					}
					locator, _ := reference["referenceLocator"].(string)
					if strings.HasPrefix(locator, "pkg:oci/") {
						reference["referenceLocator"] = "pkg:oci/" + url.PathEscape(subjectName) + "@" + subjectDigest + "?arch=" + url.QueryEscape(platform.Arch.Oci())
						purlUpdated = true
					}
				}
				if !purlUpdated {
					return fmt.Errorf("generated SPDX image SBOM %q has no root OCI purl", filename)
				}
			}
			pkg["externalRefs"] = references
			break
		}
		if !rootFound {
			return fmt.Errorf("generated SPDX SBOM %q has no root package %q", filename, subjectName)
		}
	} else if strings.HasSuffix(filename, ".cdx.json") {
		format = "cyclonedx-json@1.6"
		metadata, ok := document["metadata"].(map[string]any)
		if !ok {
			return fmt.Errorf("generated CycloneDX SBOM %q has no metadata", filename)
		}
		metadata["timestamp"] = formattedTime
		component, ok := metadata["component"].(map[string]any)
		if !ok {
			return fmt.Errorf("generated CycloneDX SBOM %q has no metadata component", filename)
		}
		oldRef, _ := component["bom-ref"].(string)
		newRef := "urn:bifroest:artifact:" + strings.TrimPrefix(subjectDigest, "sha256:")
		component["bom-ref"] = newRef
		if oldRef != "" && oldRef != newRef {
			dependencies, _ := document["dependencies"].([]any)
			for _, rawDependency := range dependencies {
				dependency, ok := rawDependency.(map[string]any)
				if !ok {
					continue
				}
				if dependency["ref"] == oldRef {
					dependency["ref"] = newRef
				}
				dependsOn, _ := dependency["dependsOn"].([]any)
				for index, ref := range dependsOn {
					if ref == oldRef {
						dependsOn[index] = newRef
					}
				}
			}
		}
		component["hashes"] = []map[string]string{{
			"alg":     "SHA-256",
			"content": strings.TrimPrefix(subjectDigest, "sha256:"),
		}}
		component["properties"] = []map[string]string{
			{"name": "bifroest:target:architecture", "value": platform.Arch.Oci()},
			{"name": "bifroest:target:os", "value": platform.Os.String()},
		}
	} else {
		return fmt.Errorf("cannot normalize unknown SBOM format %q", filename)
	}
	if len(licenseInventory) > 0 && licenseInventory[0] != nil {
		if err := enrichSbomLicenses(document, format, subjectName, licenseInventory[0]); err != nil {
			return fmt.Errorf("cannot enrich generated SBOM %q with licenses: %w", filename, err)
		}
	}
	identity := fmt.Sprintf("%s|%s|%s|%s", artifactType, subjectName, subjectDigest, format)
	if format == "spdx-json@2.3" {
		hash := sha256.Sum256([]byte(identity))
		document["documentNamespace"] = "https://github.com/engity-com/bifroest/sbom/" + hex.EncodeToString(hash[:])
	} else {
		document["serialNumber"] = uuid.NewSHA1(uuid.NameSpaceURL, []byte(identity)).URN()
	}
	normalized, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode normalized SBOM %q: %w", filename, err)
	}
	normalized = append(normalized, '\n')
	if err := gos.WriteFile(filename, normalized, 0644); err != nil {
		return fmt.Errorf("cannot write normalized SBOM %q: %w", filename, err)
	}
	return nil
}
