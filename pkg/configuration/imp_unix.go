//go:build unix

package configuration

var (
	defaultImpAlternativesLocation = `/var/lib/engity/bifroest/imp/binaries/{{.version}}/{{.os}}-{{.arch}}{{.ext}}`
)
