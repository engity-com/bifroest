// Package conpty inventories the pinned Microsoft ConPTY interface library.
// Windows relays use its public release API with the inbox console host,
// including on systems predating kernel32!ReleasePseudoConsole.
package conpty

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	_ "embed"
	"fmt"
)

//go:generate go run ./generate

const (
	Name            = "Microsoft.Windows.Console.ConPTY"
	VersionIndexURL = "https://api.nuget.org/v3-flatcontainer/microsoft.windows.console.conpty/index.json"
)

//go:embed pin.json
var PinJSON []byte

var (
	pinned        = mustParsePin(PinJSON)
	Version       = pinned.Version
	PackageSHA256 = pinned.PackageSHA256
	PackageURL    = PackageURLForVersion(Version)
	// Payloads contains only the interface DLLs. Microsoft's missing-OpenConsole
	// path selects System32's conhost, including on Nano Server.
	Payloads = pinned.Payloads
)

//go:embed LICENSE.txt
var License string

type Payload struct {
	Arch    string `json:"arch"`
	SHA256  string `json:"sha256"`
	Source  string `json:"-"`
	Machine uint16 `json:"-"`
}

func (p Payload) Filename() string { return "assets/" + p.Arch + "/conpty.dll" }

func (p Payload) Verify(raw []byte) error {
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != p.SHA256 {
		return fmt.Errorf("ConPTY %s payload digest mismatch", p.Arch)
	}
	file, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("ConPTY %s payload is not a PE file: %w", p.Arch, err)
	}
	defer file.Close()
	if file.Machine != p.Machine || file.Characteristics&pe.IMAGE_FILE_DLL == 0 {
		return fmt.Errorf("ConPTY %s payload has an unexpected machine or is not a DLL", p.Arch)
	}
	return nil
}
