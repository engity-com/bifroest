package common

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// A single-link output can be excluded from a protected directory by its open
// handle and ancestor identities. The mount check prevents treating a bind mount
// of a protected subtree as an unrelated path. Uncertain cases use the inventory
// check instead.
type outputLocation struct {
	file      fs.FileInfo
	ancestors []fs.FileInfo
	mount     outputMount
}

func inspectOutputLocation(ctx context.Context, output *os.File, info fs.FileInfo) (*outputLocation, error) {
	path, mount, unique := locateSingleLinkOutput(output, info)
	if !unique || !filepath.IsAbs(path) {
		return nil, nil
	}
	current, err := os.Stat(path)
	if err != nil || !os.SameFile(info, current) {
		return nil, nil
	}
	result := &outputLocation{file: info, mount: mount}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := os.Stat(parent)
		if err != nil || !info.IsDir() {
			return nil, nil
		}
		result.ancestors = append(result.ancestors, info)
		if filepath.Dir(parent) == parent {
			return result, nil
		}
	}
}

func (this *outputLocation) excludesDirectory(ctx context.Context, directory, description string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	protected, err := os.Stat(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot inspect protected directory %q: %w", directory, err)
	}
	if !protected.IsDir() {
		if os.SameFile(this.file, protected) {
			return false, fmt.Errorf("standard output must not replace %s %q", description, directory)
		}
		return true, nil
	}
	for _, ancestor := range this.ancestors {
		if os.SameFile(ancestor, protected) {
			return false, fmt.Errorf("standard output must not replace %s inside %q", description, directory)
		}
	}
	return this.mount.matches(directory), nil
}

func hasMountBelow(directory string, mounts []string) bool {
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return true
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return true
	}
	for _, mount := range mounts {
		relative, err := filepath.Rel(canonical, mount)
		if err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
