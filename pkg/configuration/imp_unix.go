//go:build unix

package configuration

var (
	defaultImpAlternativesLocation = `/var/lib/engity/bifroest/imp/binaries/{{.Version}}/{{.Os}}-{{.Architecture}}{{.Ext}}`
)
