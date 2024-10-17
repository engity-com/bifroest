//go:build unix

package configuration

var (
	defaultAlternativesLocation = `/var/lib/engity/bifroest/binaries/{{.version}}/{{.os}}-{{.arch}}{{.ext}}`
)
