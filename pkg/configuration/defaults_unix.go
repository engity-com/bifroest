//go:build unix && !darwin

package configuration

const DefaultRef = "/etc/engity/bifroest/configuration.yaml"

type Opts struct {
	Configuration Configuration `flag:"configuration" short:"c" default:"/etc/engity/bifroest/configuration.yaml" description:"Configuration which should be used."`
}

type StrOpts struct {
	Configuration string `flag:"configuration" short:"c" default:"/etc/engity/bifroest/configuration.yaml" description:"Configuration which should be used."`
}
