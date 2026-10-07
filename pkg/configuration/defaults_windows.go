//go:build windows

package configuration

const DefaultRef = `C:\ProgramData\Engity\Bifroest\configuration.yaml`

type Opts struct {
	Configuration Configuration `flag:"configuration" short:"c" default:"C:\\ProgramData\\Engity\\Bifroest\\configuration.yaml" description:"Configuration which should be used."`
}

type StrOpts struct {
	Configuration string `flag:"configuration" short:"c" default:"C:\\ProgramData\\Engity\\Bifroest\\configuration.yaml" description:"Configuration which should be used."`
}
