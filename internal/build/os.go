package build

import (
	"runtime"
	"strings"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

var Goos = func() sys.Os {
	var buf sys.Os
	common.Must(buf.Set(runtime.GOOS))
	return buf
}()

func OsToLdFlags(o sys.Os) string {
	return "-X main.os=" + o.String()
}

func ExtendPathWith(forOs sys.Os, source sys.EnvVars, paths ...string) sys.EnvVars {
	result := source.Clone()
	if result == nil {
		result = sys.EnvVars{}
	}
	if len(paths) == 0 {
		return result
	}

	var delim string
	switch forOs {
	case sys.OsWindows:
		delim = ";"
	default:
		delim = ":"
	}

	existing := result["PATH"]
	if existing != "" {
		result["PATH"] = existing + delim + strings.Join(paths, delim)
	} else {
		result["PATH"] = strings.Join(paths, delim)
	}

	return result
}

func ArchiveFormatFor(os sys.Os) ArchiveFormat {
	switch os {
	case sys.OsWindows:
		return ArchiveFormatZip
	default:
		return ArchiveFormatTgz
	}
}

func SetOsToEnv(o sys.Os, env interface{ SetEnv(key, val string) }) {
	env.SetEnv("GOOS", o.String())
}
