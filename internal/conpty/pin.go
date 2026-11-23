package conpty

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/Masterminds/semver/v3"
)

const MaximumPackageBytes = 32 << 20

type Pin struct {
	Version       string    `json:"version"`
	PackageSHA256 string    `json:"packageSHA256"`
	Payloads      []Payload `json:"payloads"`
}

func stableVersion(text string) (*semver.Version, error) {
	version, err := semver.StrictNewVersion(text)
	if err != nil || version.Prerelease() != "" || version.Metadata() != "" {
		return nil, fmt.Errorf("ConPTY version %q is not a canonical stable release", text)
	}
	return version, nil
}

func layout() []Payload {
	return []Payload{
		{Arch: "386", Source: "runtimes/win-x86/native/conpty.dll", Machine: pe.IMAGE_FILE_MACHINE_I386},
		{Arch: "amd64", Source: "runtimes/win-x64/native/conpty.dll", Machine: pe.IMAGE_FILE_MACHINE_AMD64},
		{Arch: "arm64", Source: "runtimes/win-arm64/native/conpty.dll", Machine: pe.IMAGE_FILE_MACHINE_ARM64},
	}
}

func validDigest(text string) bool {
	raw, err := hex.DecodeString(text)
	return err == nil && len(raw) == sha256.Size && strings.ToLower(text) == text
}

func ParsePin(raw []byte) (Pin, error) {
	var pin Pin
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pin); err != nil {
		return pin, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return pin, fmt.Errorf("ConPTY pin has trailing data")
	}
	if _, err := stableVersion(pin.Version); err != nil {
		return pin, err
	}
	if !validDigest(pin.PackageSHA256) {
		return pin, fmt.Errorf("ConPTY pin has an invalid package digest")
	}
	expected := layout()
	if len(pin.Payloads) != len(expected) {
		return pin, fmt.Errorf("ConPTY pin must contain every supported architecture")
	}
	for index, payload := range pin.Payloads {
		if payload.Arch != expected[index].Arch || !validDigest(payload.SHA256) {
			return pin, fmt.Errorf("invalid ConPTY payload pin at index %d", index)
		}
		pin.Payloads[index] = expected[index]
		pin.Payloads[index].SHA256 = payload.SHA256
	}
	return pin, nil
}

func mustParsePin(raw []byte) Pin {
	pin, err := ParsePin(raw)
	if err != nil {
		panic(err)
	}
	return pin
}

func (p Pin) Marshal() ([]byte, error) {
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, err := ParsePin(raw); err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func PackageURLForVersion(version string) string {
	return "https://api.nuget.org/v3-flatcontainer/microsoft.windows.console.conpty/" + version + "/microsoft.windows.console.conpty." + version + ".nupkg"
}

// LatestStable returns no downgrade and never selects a prerelease.
func LatestStable(current string, index []byte) (string, error) {
	selected, err := stableVersion(current)
	if err != nil {
		return "", err
	}
	var versions struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(index, &versions); err != nil {
		return "", err
	}
	found := false
	for _, text := range versions.Versions {
		candidate, err := semver.StrictNewVersion(text)
		if err != nil {
			return "", fmt.Errorf("unsupported ConPTY version in NuGet index: %q", text)
		}
		if candidate.Prerelease() != "" {
			continue
		}
		if _, err := stableVersion(text); err != nil {
			return "", err
		}
		found = true
		if candidate.GreaterThan(selected) {
			selected = candidate
		}
	}
	if !found {
		return "", fmt.Errorf("NuGet index has no stable ConPTY releases")
	}
	return selected.String(), nil
}

// InspectPackage reads only fixed whitelist members, validates package identity,
// license and every PE machine, and returns one consistent pin/payload snapshot.
// expectedSHA256 is mandatory for pinned regeneration; discovery computes a new
// pin from the official NuGet response for review in the dependency-update PR.
func InspectPackage(version string, raw []byte, expectedSHA256 string) (Pin, map[string][]byte, error) {
	pin := Pin{Version: version, PackageSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), Payloads: layout()}
	fail := func(err error) (Pin, map[string][]byte, error) { return Pin{}, nil, err }
	if _, err := stableVersion(version); err != nil {
		return fail(err)
	}
	if len(raw) > MaximumPackageBytes {
		return fail(fmt.Errorf("ConPTY package exceeds size limit"))
	}
	if expectedSHA256 != "" && pin.PackageSHA256 != expectedSHA256 {
		return fail(fmt.Errorf("ConPTY package digest mismatch"))
	}
	archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return fail(err)
	}
	read := func(name string, maximum int64) ([]byte, error) {
		var match *zip.File
		for _, file := range archive.File {
			if file.Name == name {
				if match != nil || !file.Mode().IsRegular() || file.UncompressedSize64 > uint64(maximum) {
					return nil, fmt.Errorf("invalid or duplicate ConPTY package member %s", name)
				}
				match = file
			}
		}
		if match == nil {
			return nil, fmt.Errorf("missing ConPTY package member %s", name)
		}
		reader, err := match.Open()
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maximum {
			return nil, fmt.Errorf("ConPTY package member exceeds size limit")
		}
		return data, nil
	}
	nuspec, err := read(Name+".nuspec", 64<<10)
	if err != nil {
		return fail(err)
	}
	var metadata struct {
		XMLName  xml.Name `xml:"package"`
		Metadata struct {
			ID      string `xml:"id"`
			Version string `xml:"version"`
			License struct {
				Type string `xml:"type,attr"`
				Text string `xml:",chardata"`
			} `xml:"license"`
		} `xml:"metadata"`
	}
	if err := xml.Unmarshal(nuspec, &metadata); err != nil {
		return fail(err)
	}
	if metadata.Metadata.ID != Name || metadata.Metadata.Version != version || metadata.Metadata.License.Type != "expression" || strings.TrimSpace(metadata.Metadata.License.Text) != "MIT" {
		return fail(fmt.Errorf("unexpected ConPTY NuGet identity, version or license"))
	}
	files := make(map[string][]byte, len(pin.Payloads))
	for index := range pin.Payloads {
		payload := &pin.Payloads[index]
		data, err := read(payload.Source, 2<<20)
		if err != nil {
			return fail(err)
		}
		payload.SHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
		if err := payload.Verify(data); err != nil {
			return fail(err)
		}
		files[payload.Filename()] = data
	}
	return pin, files, nil
}
