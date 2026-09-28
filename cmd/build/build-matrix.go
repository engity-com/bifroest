package main

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/sys"
)

const binaryLinuxExtendedImage = "ghcr.io/engity-com/build-images/build:debian12@sha256:94b2f0b0b2c7bb429dff0571fcc135db6914c73612c82c8cea3d30e747b0c2f5"

type buildMatrix[T any] struct {
	Include []T `json:"include"`
}

type buildTestMatrixEntry struct {
	Os     string `json:"os"`
	Runner string `json:"runner"`
}

type buildBinaryMatrixEntry struct {
	Os      string `json:"os"`
	Arch    string `json:"arch"`
	Edition string `json:"edition"`
	Runner  string `json:"runner"`
	Image   string `json:"image"`
}

type buildEnvironmentMatrices struct {
	Tests     buildMatrix[buildTestMatrixEntry]
	Host      buildMatrix[buildBinaryMatrixEntry]
	Container buildMatrix[buildBinaryMatrixEntry]
}

func (this *build) buildMatrices() (buildEnvironmentMatrices, error) {
	result := buildEnvironmentMatrices{
		Tests:     buildMatrix[buildTestMatrixEntry]{Include: []buildTestMatrixEntry{}},
		Host:      buildMatrix[buildBinaryMatrixEntry]{Include: []buildBinaryMatrixEntry{}},
		Container: buildMatrix[buildBinaryMatrixEntry]{Include: []buildBinaryMatrixEntry{}},
	}
	seenTestOs := map[sys.Os]bool{}
	// The evaluator may run on another host than the Linux package job.
	for p := range this.platforms(false, sys.OsLinux, sys.ArchAmd64) {
		entry := buildBinaryMatrixEntry{Os: p.Os.String(), Arch: p.Arch.String(), Edition: p.Edition.String()}
		switch p.Os {
		case sys.OsLinux:
			entry.Runner = "ubuntu-latest"
			if p.Edition == sys.EditionExtended {
				entry.Image = binaryLinuxExtendedImage
			}
		case sys.OsWindows:
			entry.Runner = "windows-latest"
		default:
			return result, fmt.Errorf("no binary runner configured for %s", p.Os)
		}
		if !seenTestOs[p.Os] {
			result.Tests.Include = append(result.Tests.Include, buildTestMatrixEntry{Os: p.Os.String(), Runner: entry.Runner})
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
