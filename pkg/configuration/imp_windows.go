//go:build windows

package configuration

var (
	defaultImpAlternativesLocation = `C:\ProgramData\Engity\Bifroest\imp\binaries\{{.Version}}\{{.Os}}-{{.Architecture}}{{.Ext}}`
)
