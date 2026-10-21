//go:build darwin

package configuration

const DefaultFilename = "/Library/Application Support/Engity/Bifroest/configuration.yaml"

type Opts struct {
	Configuration *Configuration `flag:"configuration" short:"c" default:"/Library/Application Support/Engity/Bifroest/configuration.yaml" description:"Configuration which should be used."`
}

type StrOpts struct {
	Configuration string `flag:"configuration" short:"c" default:"/Library/Application Support/Engity/Bifroest/configuration.yaml" description:"Configuration which should be used."`
}
