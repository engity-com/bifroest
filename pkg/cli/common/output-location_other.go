//go:build !linux && !darwin && !windows

package common

import (
	"io/fs"
	"os"
)

type outputMount struct{}

func locateSingleLinkOutput(*os.File, fs.FileInfo) (string, outputMount, bool) {
	return "", outputMount{}, false
}

func (outputMount) matches(string) bool { return false }
