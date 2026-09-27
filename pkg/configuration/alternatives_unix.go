//go:build unix && !darwin

package configuration

var (
	defaultAlternativesLocation = `/var/lib/engity/bifroest/binaries/{{.version}}/{{.os}}-{{.arch}}-{{.edition}}{{.ext}}`
)
