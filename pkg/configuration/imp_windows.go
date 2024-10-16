//go:build windows

package configuration

var (
	defaultImpAlternativesLocation = `C:\ProgramData\Engity\Bifroest\imp\binaries\{{.version}}\{{.os}}-{{.arch}}{{.ext}}`
)
