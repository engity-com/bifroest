// Package browser validates build-time inventories, not signed provenance or
// source equivalence. Source-only Go builds do not require generated assets.
package browser

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"slices"
	"strings"
)

const Filename = "browser-build.json"
const ArchiveFilename = "BROWSER_BUILD.json"
const MaximumManifestBytes = 512 << 10
const Scope = "built-assets-and-conservative-components-not-source-attestation"

type File struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type Component struct {
	Ecosystem         string   `json:"ecosystem"`
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	License           string   `json:"license"`
	Integrity         string   `json:"integrity"`
	LicenseTextSource string   `json:"licenseTextSource"`
	Artifacts         []string `json:"artifacts"`
}

type Patch struct {
	Component   string `json:"component"`
	Description string `json:"description"`
}

type Manifest struct {
	Schema               string      `json:"schema"`
	Scope                string      `json:"scope"`
	Revision             string      `json:"revision"`
	Dirty                bool        `json:"dirty"`
	Bun                  string      `json:"bun"`
	Node                 string      `json:"node"`
	Go                   string      `json:"go"`
	Assets               []File      `json:"assets"`
	Inputs               []File      `json:"inputs"`
	Components           []Component `json:"components"`
	LocalBundlingPatches []Patch     `json:"localBundlingPatches"`
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var npmNamePattern = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
var versionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?$`)

func Decode(raw []byte) (*Manifest, error) {
	if len(raw) == 0 || len(raw) > MaximumManifestBytes {
		return nil, fmt.Errorf("browser manifest size is invalid")
	}
	var result Manifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("browser manifest has trailing data")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if string(fields["dirty"]) != "true" && string(fields["dirty"]) != "false" {
		return nil, fmt.Errorf("browser manifest lacks explicit source cleanliness")
	}
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return &result, nil
}

func Read(root fs.FS, name string) (*Manifest, []byte, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumManifestBytes {
		_ = file.Close()
		return nil, nil, fmt.Errorf("browser manifest file size/type is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaximumManifestBytes+1))
	closeErr := file.Close()
	if err != nil {
		return nil, nil, err
	}
	if closeErr != nil {
		return nil, nil, closeErr
	}
	m, err := Decode(raw)
	if err != nil {
		return nil, nil, err
	}
	return m, raw, nil
}

func (m *Manifest) Validate() error {
	if m == nil || m.Schema != "bifroest-browser-build-v1" || m.Scope != Scope || !revisionPattern.MatchString(m.Revision) || m.Bun != "1.4.4" || m.Node != "26.9.0" || m.Go != "go1.27.3" {
		return fmt.Errorf("unsupported browser manifest or toolchain")
	}
	for _, group := range []struct {
		files   []File
		maximum int64
	}{{m.Assets, 8 << 20}, {m.Inputs, 8 << 20}} {
		if len(group.files) == 0 || len(group.files) > 2048 {
			return fmt.Errorf("browser inventory file count is invalid")
		}
		seen := map[string]bool{}
		var size int64
		for _, file := range group.files {
			if !fs.ValidPath(file.Name) || file.Name == "." || strings.ContainsAny(file.Name, "\\:\x00\r\n") || len(file.Name) > 1024 || seen[strings.ToLower(file.Name)] || file.Bytes < 0 || file.Bytes > group.maximum || !digestPattern.MatchString(file.SHA256) {
				return fmt.Errorf("browser inventory file is invalid: %q", file.Name)
			}
			seen[strings.ToLower(file.Name)] = true
			size += file.Bytes
		}
		if size > 64<<20 {
			return fmt.Errorf("browser inventory total size is invalid")
		}
	}
	assets := map[string]bool{}
	for _, file := range m.Assets {
		assets[file.Name] = true
	}
	if assets[Filename] {
		return fmt.Errorf("browser inventory cannot recursively inventory itself")
	}
	for _, name := range []string{"README.txt", "index.html", "go-wasm-exec.js", "browser-key-worker.js", "browser-transfer-worker.js", "browser-evidence-worker.js", "browser-key.wasm", "browser-transfer.wasm", "browser-evidence.wasm.gz", "third-party-licenses.txt", "browser-key-licenses.txt", "browser-transfer-licenses.txt", "browser-evidence-licenses.txt", "frontend-components.json", "browser-key-components.json", "browser-transfer-components.json", "browser-evidence-components.json"} {
		if !assets[name] {
			return fmt.Errorf("browser inventory lacks %s", name)
		}
	}
	if len(m.Components) == 0 || len(m.Components) > 1024 {
		return fmt.Errorf("browser component count is invalid")
	}
	seen := map[string]bool{}
	for _, component := range m.Components {
		key := component.Ecosystem + "/" + component.Name + "@" + component.Version
		if seen[key] || !versionPattern.MatchString(component.Version) || component.Name == "" || len(component.Name) > 256 || strings.ContainsAny(component.Name, "\x00\r\n") || !slices.Contains([]string{"MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "0BSD", "(MIT OR CC0-1.0)", "Apache-2.0 AND BSD-3-Clause AND MIT"}, component.License) || component.LicenseTextSource == "" || len(component.LicenseTextSource) > 1024 || len(component.Artifacts) == 0 {
			return fmt.Errorf("invalid browser component %q", key)
		}
		seen[key] = true
		switch component.Ecosystem {
		case "npm":
			encoded, ok := strings.CutPrefix(component.Integrity, "sha512-")
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if !npmNamePattern.MatchString(component.Name) || !ok || err != nil || len(decoded) != 64 || base64.StdEncoding.EncodeToString(decoded) != encoded {
				return fmt.Errorf("invalid npm component integrity %q", key)
			}
		case "golang":
			if !strings.Contains(component.Name, ".") || strings.ContainsAny(component.Name, " @?#%\\") || component.Integrity != "" {
				return fmt.Errorf("invalid browser Go component %q", key)
			}
		case "go-runtime":
			if component.Name != "Go runtime and standard library" || component.Version != "1.27.3" || component.License != "BSD-3-Clause" || component.Integrity != "" {
				return fmt.Errorf("invalid browser runtime component")
			}
		default:
			return fmt.Errorf("unknown browser ecosystem")
		}
		for _, artifact := range component.Artifacts {
			if artifact != "browser-ui" && !assets[artifact] {
				return fmt.Errorf("browser component references unknown artifact")
			}
		}
	}
	if len(m.LocalBundlingPatches) != 1 || m.LocalBundlingPatches[0].Component != "@xterm/xterm@6.0.0" || m.LocalBundlingPatches[0].Description == "" {
		return fmt.Errorf("browser bundling patch inventory is invalid")
	}
	return nil
}

func VerifyFiles(root fs.FS, files []File) error {
	for _, expected := range files {
		file, err := root.Open(expected.Name)
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Size() != expected.Bytes {
			_ = file.Close()
			return fmt.Errorf("browser build file size/type changed: %s", expected.Name)
		}
		hash := sha256.New()
		n, err := io.Copy(hash, io.LimitReader(file, expected.Bytes+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || n != expected.Bytes || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
			return fmt.Errorf("browser build file digest changed: %s", expected.Name)
		}
	}
	return nil
}

// VerifyAssets rejects additional embedded files as well as missing/changed ones.
func (m *Manifest) VerifyAssets(root fs.FS) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if err := VerifyFiles(root, m.Assets); err != nil {
		return err
	}
	expected := map[string]bool{Filename: true}
	for _, file := range m.Assets {
		expected[file.Name] = true
	}
	return fs.WalkDir(root, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 || !expected[name] {
			return fmt.Errorf("unlisted or linked browser asset %s", name)
		}
		return nil
	})
}
