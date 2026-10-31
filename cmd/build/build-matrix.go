package main

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/sys"
)

const binaryLinuxAmd64Image = "ghcr.io/engity-com/build-images/build:debian12-amd64@sha256:083b2302959b7ae61f41f7c5c8f796c04802494ebbf2827f201a3369fd710cb2"

var binaryLinuxExtendedImages = map[sys.Arch]string{
	sys.Arch386:   "ghcr.io/engity-com/build-images/build:debian12-386@sha256:c2f72dbf5ca6ece2f158fc391f7f901c5fdd665819c69a91da7c4797028d9d73",
	sys.ArchAmd64: binaryLinuxAmd64Image,
	sys.ArchArmV7: "ghcr.io/engity-com/build-images/build:debian12-armv7@sha256:4cc51d3cd2695642ec38a75d27e1ca61ac341ba9af54a72dc866582104799c47",
	sys.ArchArm64: "ghcr.io/engity-com/build-images/build:debian12-arm64@sha256:b7b8ec2fb8525e0644831c6237b39ef9d8b38ac13808f298e78648ee2361fef4",
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
