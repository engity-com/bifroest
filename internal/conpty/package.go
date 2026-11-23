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
	Name          = "Microsoft.Windows.Console.ConPTY"
	Version       = "1.25.261109001"
	PackageSHA256 = "3d77f535df848e44225c2a8912ac844fecb23f3057732b639f3034b587496f09"
	PackageURL    = "https://api.nuget.org/v3-flatcontainer/microsoft.windows.console.conpty/" + Version + "/microsoft.windows.console.conpty." + Version + ".nupkg"
)

//go:embed LICENSE.txt
var License string

type Payload struct {
	Arch    string
	Source  string
	SHA256  string
	Machine uint16
}

// Payloads contains only the interface DLLs, not the GUI-dependent OpenConsole
// executable. The DLL's supported missing-OpenConsole path selects System32's
// conhost.exe; its public release API still releases the ConDrv reference.
var Payloads = []Payload{
	{Arch: "386", Source: "runtimes/win-x86/native/conpty.dll", SHA256: "914c7eb6840a5cb477e5f2fdd26610ba4272803b96866123cb87e21a8a2366cd", Machine: pe.IMAGE_FILE_MACHINE_I386},
	{Arch: "amd64", Source: "runtimes/win-x64/native/conpty.dll", SHA256: "e971856f89748dc3b458125e9afdd79b5e9574a7c937676116d3cbbd3b71f492", Machine: pe.IMAGE_FILE_MACHINE_AMD64},
	{Arch: "arm64", Source: "runtimes/win-arm64/native/conpty.dll", SHA256: "3608cef830a1c4fbbf3981594ad3f64ebe2df6db98fe43a48a4ca7d2875d8959", Machine: pe.IMAGE_FILE_MACHINE_ARM64},
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
