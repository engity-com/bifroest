package test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/engity-com/bifroest/pkg/errors"
)

const suiteSuffix = "_bftest.lua"

type nameFilter struct{ includes, excludes []*regexp.Regexp }

func compileFilter(includes, excludes []string) (nameFilter, error) {
	var result nameFilter
	for _, group := range []struct {
		source []string
		target *[]*regexp.Regexp
	}{{includes, &result.includes}, {excludes, &result.excludes}} {
		if len(group.source) > 64 {
			return result, invalid("too many test name filters")
		}
		for _, expression := range group.source {
			if len(expression) > maxString {
				return result, invalid("test name filter limit exceeded")
			}
			compiled, err := regexp.Compile(expression)
			if err != nil {
				return result, invalid("invalid test name regular expression")
			}
			*group.target = append(*group.target, compiled)
		}
	}
	return result, nil
}

func (this nameFilter) matches(name string) bool {
	matched := len(this.includes) == 0
	for _, expression := range this.includes {
		matched = matched || expression.MatchString(name)
	}
	if !matched {
		return false
	}
	for _, expression := range this.excludes {
		if expression.MatchString(name) {
			return false
		}
	}
	return true
}

// Discovery follows directory and file symlinks, including links outside the
// starting tree. Content access from Lua has its own, separate confinement root.
// Canonical paths and file identities prevent cycles and duplicate execution.
func discoverFiles(ctx context.Context, paths []string) ([]string, []Result, []string) {
	var files []string
	var failures []Result
	var packages []string
	seenPaths := map[string]bool{}
	var seenFiles, seenDirectories []os.FileInfo
	entries := 0
	var walk func(string, bool, int)
	fail := func(path string, err error, message string) {
		result := failureResult("discovery", err, message)
		result.Source = path
		failures = append(failures, result)
	}
	contains := func(infos []os.FileInfo, info os.FileInfo) bool {
		for _, previous := range infos {
			if os.SameFile(previous, info) {
				return true
			}
		}
		return false
	}
	walk = func(path string, explicit bool, depth int) {
		if err := ctx.Err(); err != nil {
			fail(path, errors.System.Newf("%w", err), "suite discovery canceled")
			return
		}
		entries++
		if entries > 100_000 {
			if entries == 100_001 {
				fail(path, invalid("suite discovery entry limit exceeded"), "suite discovery entry limit exceeded")
			}
			return
		}
		if depth > 256 {
			fail(path, invalid("suite directory depth limit exceeded"), "suite directory depth limit exceeded")
			return
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			fail(path, err, "cannot resolve suite input")
			return
		}
		canonical, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			fail(path, err, "cannot resolve suite input")
			return
		}
		info, err := os.Stat(canonical)
		if err != nil {
			fail(path, err, "cannot inspect suite input")
			return
		}
		if info.IsDir() {
			if explicit {
				packages = append(packages, canonical)
			}
			if seenPaths[canonical] || contains(seenDirectories, info) {
				return
			}
			seenPaths[canonical] = true
			seenDirectories = append(seenDirectories, info)
			directory, err := os.Open(canonical)
			if err != nil {
				fail(path, err, "cannot read suite directory")
				return
			}
			defer directory.Close()
			for {
				children, readErr := directory.ReadDir(256)
				for _, child := range children {
					if entries > 100_000 || ctx.Err() != nil {
						return
					}
					// Count ignored entries too, without retaining an unbounded
					// directory listing. Final canonical file order is sorted below.
					if child.IsDir() || child.Type()&os.ModeSymlink != 0 || strings.HasSuffix(child.Name(), suiteSuffix) {
						walk(filepath.Join(canonical, child.Name()), false, depth+1)
					} else {
						entries++
						if entries == 100_001 {
							fail(path, invalid("suite discovery entry limit exceeded"), "suite discovery entry limit exceeded")
						}
					}
				}
				if readErr == io.EOF {
					return
				}
				if readErr != nil {
					fail(path, readErr, "cannot read suite directory")
					return
				}
			}
		}
		if !strings.HasSuffix(filepath.Base(path), suiteSuffix) {
			if explicit {
				fail(path, invalid("suite filenames must end in _bftest.lua"), "suite filenames must end in _bftest.lua")
			}
			return
		}
		if !info.Mode().IsRegular() {
			fail(path, invalid("suite input is not a regular file"), "suite input is not a regular file")
			return
		}
		if seenPaths[canonical] || contains(seenFiles, info) {
			return
		}
		seenPaths[canonical] = true
		seenFiles = append(seenFiles, info)
		files = append(files, canonical)
	}
	for _, path := range paths {
		walk(path, true, 0)
	}
	if ctx.Err() != nil && len(failures) == 0 {
		fail("", errors.System.Newf("%w", ctx.Err()), "suite discovery canceled")
	}
	slices.Sort(files)
	return files, failures, packages
}
