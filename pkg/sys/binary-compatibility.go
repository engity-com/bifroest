package sys

var binaryCompatibilityMatrix = map[Os]map[Arch]map[Arch]struct{}{
	OsLinux: {
		ArchAmd64: {
			Arch386: struct{}{},
		},
		ArchArm64: {
			ArchArmV6: struct{}{},
			ArchArmV7: struct{}{},
		},
	},
	OsWindows: {
		ArchAmd64: {
			Arch386: struct{}{},
		},
		ArchArm64: {
			ArchArmV6: struct{}{},
			ArchArmV7: struct{}{},
		},
	},
}

func IsBinaryCompatibleWithHost(binaryOs Os, binaryArch Arch, hostOs Os, hostArch Arch) bool {
	if !binaryOs.IsEqualTo(hostOs) {
		return false
	}
	if binaryArch.IsEqualTo(hostArch) {
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
