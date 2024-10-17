//go:build windows

package configuration

var (
	defaultAlternativesLocation = `C:\ProgramData\Engity\Bifroest\binaries\{{.version}}\{{.os}}-{{.arch}}{{.ext}}`
)
