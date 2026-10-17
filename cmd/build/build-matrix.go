package main

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/sys"
)

const binaryLinuxAmd64Image = "ghcr.io/engity-com/build-images/build:debian12-amd64@sha256:c8493fc95e96ab25422165d89042dc342e139e64813cfc854088806877daeca3"

var binaryLinuxExtendedImages = map[sys.Arch]string{
	sys.Arch386:   "ghcr.io/engity-com/build-images/build:debian12-386@sha256:eeddf9dfec6836148994e089be21931a244fc3258476119b3231f929560187dc",
	sys.ArchAmd64: binaryLinuxAmd64Image,
	sys.ArchArmV7: "ghcr.io/engity-com/build-images/build:debian12-armv7@sha256:d4092258ca85e75f5f8cd8f8fc0b621ddaea45128b133bf2b25808efa6655a76",
	sys.ArchArm64: "ghcr.io/engity-com/build-images/build:debian12-arm64@sha256:2b9d53173aa1a94dc4144d1e9a747c90addedb48f36e7bdc789556f9ca28dc33",
}

type buildMatrix[T any] struct {
	Include []T `json:"include"`
}

type buildTestMatrixEntry struct {
	Os     string `json:"os"`
	Runner string `json:"runner"`
	Image  string `json:"image"`
}

type buildBinaryMatrixEntry struct {
	Os      string `json:"os"`
	Arch    string `json:"arch"`
	Edition string `json:"edition"`
	Runner  string `json:"runner"`
	Image   string `json:"image"`
}

type buildEnvironmentMatrices struct {
	TestHost      buildMatrix[buildTestMatrixEntry]
	TestContainer buildMatrix[buildTestMatrixEntry]
	Host          buildMatrix[buildBinaryMatrixEntry]
	Container     buildMatrix[buildBinaryMatrixEntry]
}

func (this *build) buildMatrices() (buildEnvironmentMatrices, error) {
	result := buildEnvironmentMatrices{
		TestHost:      buildMatrix[buildTestMatrixEntry]{Include: []buildTestMatrixEntry{}},
		TestContainer: buildMatrix[buildTestMatrixEntry]{Include: []buildTestMatrixEntry{}},
		Host:          buildMatrix[buildBinaryMatrixEntry]{Include: []buildBinaryMatrixEntry{}},
		Container:     buildMatrix[buildBinaryMatrixEntry]{Include: []buildBinaryMatrixEntry{}},
	}
	seenTestOs := map[sys.Os]bool{}
	for p := range this.distributablePlatforms(false) {
		entry := buildBinaryMatrixEntry{Os: p.Os.String(), Arch: p.Arch.String(), Edition: p.Edition.String()}
		switch p.Os {
		case sys.OsLinux:
			entry.Runner = "ubuntu-latest"
			if p.Edition == sys.EditionExtended {
				var ok bool
				entry.Image, ok = binaryLinuxExtendedImages[p.Arch]
				if !ok {
					return result, fmt.Errorf("no build image configured for %s", p)
				}
			}
		case sys.OsDarwin:
			switch p.Arch {
			case sys.ArchAmd64:
				entry.Runner = "macos-15-intel"
			case sys.ArchArm64:
				entry.Runner = "macos-15"
			default:
				return result, fmt.Errorf("no Darwin runner configured for %s", p)
			}
		case sys.OsWindows:
			entry.Runner = "windows-latest"
		default:
			return result, fmt.Errorf("no binary runner configured for %s", p.Os)
		}
		if !seenTestOs[p.Os] {
			testEntry := buildTestMatrixEntry{Os: p.Os.String(), Runner: entry.Runner}
			if p.Os == sys.OsLinux {
				testEntry.Image = binaryLinuxAmd64Image
				result.TestContainer.Include = append(result.TestContainer.Include, testEntry)
			} else {
				if p.Os == sys.OsDarwin {
					testEntry.Runner = "macos-15"
				}
				result.TestHost.Include = append(result.TestHost.Include, testEntry)
			}
			seenTestOs[p.Os] = true
		}
		if entry.Image == "" {
			result.Host.Include = append(result.Host.Include, entry)
		} else {
			result.Container.Include = append(result.Container.Include, entry)
		}
	}
	return result, nil
}
