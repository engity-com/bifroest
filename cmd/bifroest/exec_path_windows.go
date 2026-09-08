//go:build windows

package main

import (
	"fmt"
	goos "os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func resolveExecPath(file, workingDirectory string, environment map[string]string) (string, error) {
	path := environmentValue(environment, "PATH")
	extensions := executableExtensions(file, environmentValue(environment, "PATHEXT"))
	directories := filepath.SplitList(path)
	if strings.ContainsAny(file, `:/\\`) {
		directories = []string{""}
	}
	for _, directory := range directories {
		candidate := resolveTargetPath(filepath.Join(directory, file), workingDirectory)
		for _, extension := range extensions {
			if info, err := goos.Stat(candidate + extension); err == nil && !info.IsDir() {
				return candidate + extension, nil
			}
		}
	}
	return "", fmt.Errorf("%s: %w", file, exec.ErrNotFound)
}

func environmentValue(environment map[string]string, name string) string {
	if value, ok := environment[name]; ok {
		for key := range environment {
			if key != name && strings.EqualFold(key, name) {
				delete(environment, key)
			}
		}
		return value
	}
	var matches []string
	for key := range environment {
		if strings.EqualFold(key, name) {
			matches = append(matches, key)
		}
	}
	if len(matches) == 0 {
		return ""
	}
	sort.Strings(matches)
	value := environment[matches[0]]
	for _, key := range matches {
		delete(environment, key)
	}
	environment[name] = value
	return value
}

func executableExtensions(file, pathExt string) []string {
	if pathExt == "" {
		pathExt = ".COM;.EXE;.BAT;.CMD"
	}
	var result []string
	if filepath.Ext(file) != "" {
		result = append(result, "")
	}
	for _, extension := range filepath.SplitList(pathExt) {
		if extension != "" {
			if extension[0] != '.' {
				extension = "." + extension
			}
			result = append(result, extension)
		}
	}
	return result
}

func resolveTargetPath(path, workingDirectory string) string {
	if filepath.IsAbs(path) || filepath.VolumeName(path) != "" {
		return path
	}
	currentDirectory, _ := goos.Getwd()
	if workingDirectory == "" {
		workingDirectory = currentDirectory
	} else if !filepath.IsAbs(workingDirectory) {
		workingDirectory = filepath.Join(currentDirectory, workingDirectory)
	}
	return filepath.Join(workingDirectory, path)
}
