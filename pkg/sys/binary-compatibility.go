package sys

import "runtime"

var binaryCompatibilityMatrix = map[string]map[string]map[string]struct{}{
	"linux": {
		"amd64": {
			"386": struct{}{},
		},
		"arm64": {
			"arm": struct{}{},
		},
	},
	"windows": {
		"amd64": {
			"386": struct{}{},
		},
		"arm64": {
			"arm": struct{}{},
		},
	},
}

func IsBinaryCompatibleWithHost(binaryOs, binaryArch, hostOs, hostArch string) bool {
	if binaryOs != hostOs {
		return false
	}
	if binaryArch == hostArch {
		return true
	}

	byOS, ok := binaryCompatibilityMatrix[hostOs]
	if !ok {
		return false
	}

	byArch, ok := byOS[hostArch]
	if !ok {
		return false
	}

	_, ok = byArch[binaryArch]

	return ok
}

func IsBinaryCompatibleWithArch(binaryArch, hostArch string) bool {
	return IsBinaryCompatibleWithHost(runtime.GOOS, binaryArch, runtime.GOOS, hostArch)
}
