package main

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/sys"
)

const binaryLinuxAmd64Image = "ghcr.io/engity-com/build-images/build:debian12-amd64@sha256:4c5969c27f1e4044b7f41118072505cdea482a39067549ebbb07961e948897c4"

var binaryLinuxExtendedImages = map[sys.Arch]string{
	sys.Arch386:   "ghcr.io/engity-com/build-images/build:debian12-386@sha256:ca0c8473153b9eac87208b8e29a2a60cf69a4c83bd3de7f3b411fe132546e0bd",
	sys.ArchAmd64: binaryLinuxAmd64Image,
	sys.ArchArmV7: "ghcr.io/engity-com/build-images/build:debian12-armv7@sha256:a8e14839dfa2c4eb7954b4cba5ec069a71164afe76bba72b1c66bb704b88ede4",
	sys.ArchArm64: "ghcr.io/engity-com/build-images/build:debian12-arm64@sha256:2c65dd238e88bd2efe513be00fe00e64c094bdd9220b34f8a1e4a5ae3104132c",
}

type buildMatrix[T any] struct {
	Include []T `json:"include"`
}

type buildTestMatrixEntry struct {
	Os     string `json:"os"`
	Arch   string `json:"arch"`
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
	seenTestHosts := map[string]bool{}
	for p := range this.distributablePlatforms(false) {
		entry := buildBinaryMatrixEntry{Os: p.Os.String(), Arch: p.Arch.String(), Edition: p.Edition.String()}
		testEntry := buildTestMatrixEntry{Os: p.Os.String()}
		switch p.Os {
		case sys.OsLinux:
			entry.Runner = "ubuntu-latest"
			testEntry.Arch = sys.ArchAmd64.String()
			testEntry.Runner = entry.Runner
			if p.Edition == sys.EditionExtended {
				var ok bool
				entry.Image, ok = binaryLinuxExtendedImages[p.Arch]
				if !ok {
					return result, fmt.Errorf("no build image configured for %s", p)
				}
			}
		case sys.OsDarwin:
			testEntry.Arch = p.Arch.String()
			switch p.Arch {
			case sys.ArchAmd64:
				entry.Runner = "macos-15-intel"
			case sys.ArchArm64:
				entry.Runner = "macos-15"
			default:
				return result, fmt.Errorf("no Darwin runner configured for %s", p)
			}
			testEntry.Runner = entry.Runner
		case sys.OsWindows:
			entry.Runner = "windows-latest"
			testEntry.Arch = sys.ArchAmd64.String()
			testEntry.Runner = entry.Runner
		default:
			return result, fmt.Errorf("no binary runner configured for %s", p.Os)
		}
		testKey := testEntry.Os + "/" + testEntry.Arch
		if !seenTestHosts[testKey] {
			if p.Os == sys.OsLinux {
				testEntry.Image = binaryLinuxAmd64Image
				result.TestContainer.Include = append(result.TestContainer.Include, testEntry)
			} else {
				result.TestHost.Include = append(result.TestHost.Include, testEntry)
			}
			seenTestHosts[testKey] = true
		}
		if entry.Image == "" {
			result.Host.Include = append(result.Host.Include, entry)
		} else {
			result.Container.Include = append(result.Container.Include, entry)
		}
	}
	return result, nil
}
