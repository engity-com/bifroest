package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	gos "os"
	"time"

	bib "github.com/engity-com/bifroest/internal/build"
)

const binaryBuildMetadataVersion = 1

type binaryBuildMetadata struct {
	SchemaVersion int                        `json:"schemaVersion"`
	Platform      string                     `json:"platform"`
	Version       string                     `json:"version"`
	Revision      string                     `json:"revision"`
	Vendor        string                     `json:"vendor"`
	BuildTime     time.Time                  `json:"buildTime"`
	BinaryDigest  string                     `json:"binaryDigest"`
	NoticeDigest  string                     `json:"noticeDigest"`
	Licenses      []binaryBuildLicenseModule `json:"licenses"`
}

type binaryBuildLicenseModule struct {
	Names      []string `json:"names"`
	Version    string   `json:"version"`
	Expression string   `json:"expression"`
}

func (this *buildBinary) metadataFilepath(binary *buildArtifact) string {
	return binary.buildContext.filepath(binary.Platform.FilenamePrefix(this.prefix) + ".binary-build.json")
}

func (this *buildBinary) save(binary, notice *buildArtifact) error {
	if binary.thirdPartyLicenseInventory == nil || binary.thirdPartyNoticesFilepath != notice.filepath {
		return fmt.Errorf("binary %s has no matching third-party license data", binary.Platform)
	}
	binaryDigest, err := sha256File(binary.filepath)
	if err != nil {
		return err
	}
	noticeDigest, err := sha256File(notice.filepath)
	if err != nil {
		return err
	}
	metadata := binaryBuildMetadata{
		SchemaVersion: binaryBuildMetadataVersion,
		Platform:      binary.Platform.String(),
		Version:       binary.version.String(),
		Revision:      binary.revision,
		Vendor:        binary.vendor,
		BuildTime:     binary.time,
		BinaryDigest:  binaryDigest,
		NoticeDigest:  noticeDigest,
	}
	for _, module := range binary.thirdPartyLicenseInventory.modules {
		metadata.Licenses = append(metadata.Licenses, binaryBuildLicenseModule{
			Names: module.names, Version: module.version, Expression: module.licenseExpression,
		})
	}
	if len(metadata.Licenses) == 0 {
		return fmt.Errorf("binary %s has no third-party license inventory", binary.Platform)
	}
	raw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return gos.WriteFile(this.metadataFilepath(binary), append(raw, '\n'), 0644)
}

func (this *buildBinary) load(ctx context.Context, p *bib.Platform) (*buildArtifact, *buildArtifact, error) {
	binary, err := this.newBuildFileArtifact(ctx, p, buildArtifactTypeBinary, p.Os.AppendExtToFilename(p.FilenamePrefix(this.prefix)))
	if err != nil {
		return nil, nil, err
	}
	notice, err := this.newBuildFileArtifact(ctx, p, buildArtifactTypeNotice, p.FilenamePrefix(this.prefix)+".third-party-notices.txt")
	if err != nil {
		return nil, nil, err
	}
	filename := this.metadataFilepath(binary)
	raw, err := gos.ReadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot load binary build metadata %q: %w", filename, err)
	}
	var metadata binaryBuildMetadata
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return nil, nil, fmt.Errorf("invalid binary build metadata %q: %w", filename, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, nil, fmt.Errorf("binary build metadata %q has trailing data", filename)
	}
	if metadata.SchemaVersion != binaryBuildMetadataVersion || metadata.Platform != p.String() ||
		metadata.Version != binary.version.String() || metadata.Revision != binary.revision ||
		metadata.Vendor != binary.vendor || !metadata.BuildTime.Equal(binary.time) || len(metadata.Licenses) == 0 {
		return nil, nil, fmt.Errorf("binary build metadata %q does not match the expected build", filename)
	}
	for _, item := range []struct{ filename, expected string }{
		{binary.filepath, metadata.BinaryDigest},
		{notice.filepath, metadata.NoticeDigest},
	} {
		actual, err := sha256File(item.filename)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot load binary build file %q: %w", item.filename, err)
		}
		if actual != item.expected {
			return nil, nil, fmt.Errorf("binary build file %q has digest %s instead of %s", item.filename, actual, item.expected)
		}
	}
	inventory := &thirdPartyLicenseInventory{}
	for _, module := range metadata.Licenses {
		if len(module.Names) == 0 || module.Expression == "" {
			return nil, nil, fmt.Errorf("binary build metadata %q has incomplete license data", filename)
		}
		inventory.modules = append(inventory.modules, thirdPartyLicenseModule{
			names: module.Names, version: module.Version, licenseExpression: module.Expression,
		})
	}
	binary.thirdPartyNoticesFilepath = notice.filepath
	binary.thirdPartyLicenseInventory = inventory
	return binary, notice, nil
}
