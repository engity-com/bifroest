package build

import (
	"github.com/engity-com/bifroest/pkg/sys"
)

func DoesEditionSupportBinaryFor(e sys.Edition, o sys.Os, a sys.Arch, assumedOs sys.Os, assumedArch sys.Arch) bool {
	if !IsOsAndArchSupported(o, a) {
		return false
	}

	if assumedOs == 0 {
		assumedOs = Goos
	}
	if assumedArch == 0 {
		assumedArch = Goarch
	}

	if o == sys.OsDarwin {
		return e == sys.EditionGeneric && assumedOs == o && assumedArch == a
	}

	if e == sys.EditionGeneric {
		return true
	}

	if e == sys.EditionExtended {
		buildDetails := archToDetails[a].os[o].build[archBuildKey{assumedOs, assumedArch}]
		return buildDetails.crossCc != ""
	}

	return false
}

func SetEditionToEnv(e sys.Edition, env interface{ SetEnv(key, val string) }) {
	switch e {
	case sys.EditionExtended:
		env.SetEnv("CGO_ENABLED", "1")
	default:
		env.SetEnv("CGO_ENABLED", "0")
	}
}

func EditionToLdFlags(e sys.Edition) string {
	result := "-X main.edition=" + e.String()
	if e == sys.EditionExtended {
		result += " -linkmode external"
	}
	return result
}
