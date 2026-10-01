package main

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/sys"
)

const binaryLinuxAmd64Image = "ghcr.io/engity-com/build-images/build:debian12-amd64@sha256:77fe6e3bc73897923888cefef06cc13c85c14780a62bee10db427396c2e676a4"

var binaryLinuxExtendedImages = map[sys.Arch]string{
	sys.Arch386:   "ghcr.io/engity-com/build-images/build:debian12-386@sha256:05c37d8057f5746c8a0f307799aa7fcfe45da144640e574e0213523eef14dc03",
	sys.ArchAmd64: binaryLinuxAmd64Image,
	sys.ArchArmV7: "ghcr.io/engity-com/build-images/build:debian12-armv7@sha256:a17c0530b248907a9bdbb25deb007e742554cf6a0c38ed7764b27e6b4c5564d4",
	sys.ArchArm64: "ghcr.io/engity-com/build-images/build:debian12-arm64@sha256:3246cafc40cca24b0640b20d6aa53a9c2c11b61688311ce84cc979ca61d45f20",
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
	// The evaluator may run on another host than the Linux package job.
	for p := range this.platforms(false, sys.OsLinux, sys.ArchAmd64) {
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
