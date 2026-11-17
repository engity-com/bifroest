package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	gos "os"
	"path/filepath"

	"github.com/engity-com/bifroest/internal/build/browser"
)

const browserAssetDirectory = "pkg/webui/assets"

func readBrowserBuild(root fs.FS, revision string) (*browser.Manifest, []byte, error) {
	manifest, raw, err := browser.Read(root, browserAssetDirectory+"/"+browser.Filename)
	if err != nil {
		return nil, nil, fmt.Errorf("build frontend first with mise run build:web: %w", err)
	}
	if manifest.Revision != revision {
		return nil, nil, fmt.Errorf("browser build revision differs from binary revision")
	}
	if gos.Getenv("GITHUB_ACTIONS") == "true" && manifest.Dirty {
		return nil, nil, fmt.Errorf("CI requires clean browser source inputs")
	}
	assets, err := fs.Sub(root, browserAssetDirectory)
	if err != nil {
		return nil, nil, err
	}
	if err := manifest.VerifyAssets(assets); err != nil {
		return nil, nil, err
	}
	if err := browser.VerifyFiles(root, manifest.Inputs); err != nil {
		return nil, nil, err
	}
	return manifest, raw, nil
}

func browserBuildPath(binary *buildArtifact) string {
	return binary.buildContext.filepath(binary.Platform.FilenamePrefix(binary.buildContext.build.prefix) + ".browser-build.json")
}

// The same verified bytes are staged before compilation and checked again after
// it. Packaging restores this inventory, never the packaging host's frontend.
func stageBrowserBuild(binary *buildArtifact, manifest *browser.Manifest, raw []byte) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if err := gos.WriteFile(browserBuildPath(binary), raw, 0644); err != nil {
		return err
	}
	binary.browserManifest = manifest
	binary.browserManifestRaw = bytes.Clone(raw)
	return nil
}

func appendBrowserNotices(binary *buildArtifact, root fs.FS, target io.Writer) error {
	if binary.browserManifest == nil {
		return fmt.Errorf("binary lacks browser inventory")
	}
	for _, name := range []string{"third-party-licenses.txt", "browser-key-licenses.txt", "browser-transfer-licenses.txt", "browser-evidence-licenses.txt"} {
		raw, err := fs.ReadFile(root, filepath.ToSlash(filepath.Join(browserAssetDirectory, name)))
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(target, "\n================================================================================\nBundled browser notices: %s\nSource inventory: %s (build metadata, not source attestation)\n\n%s\n", name, browser.ArchiveFilename, raw); err != nil {
			return err
		}
	}
	return nil
}

func browserManifestDigest(raw []byte) string {
	hash := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(hash[:])
}
