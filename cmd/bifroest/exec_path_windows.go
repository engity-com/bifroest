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

func ensureExecPathEnvironment(environment map[string]string) {
	if _, exists := environmentValue(environment, "PATH"); !exists {
		if path, exists := goos.LookupEnv("PATH"); exists {
			environment["PATH"] = path
		}
	}
	if _, exists := environmentValue(environment, "PATHEXT"); !exists {
		if pathExt, exists := goos.LookupEnv("PATHEXT"); exists {
			environment["PATHEXT"] = pathExt
		}
	}
}

func setExecEnvironment(environment map[string]string, key, value string) {
	for existing := range environment {
		if strings.EqualFold(existing, key) {
			delete(environment, existing)
		}
	}
	environment[key] = value
}

func resolveExecPath(file, workingDirectory string, environment map[string]string) (string, error) {
	path, _ := environmentValue(environment, "PATH")
	pathExt, _ := environmentValue(environment, "PATHEXT")
	extensions := executableExtensions(file, pathExt)
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

func environmentValue(environment map[string]string, name string) (string, bool) {
	if value, ok := environment[name]; ok {
		for key := range environment {
			if key != name && strings.EqualFold(key, name) {
				delete(environment, key)
			}
		}
		return value, true
	}
	var matches []string
	for key := range environment {
		if strings.EqualFold(key, name) {
			matches = append(matches, key)
		}
	}
	if len(matches) == 0 {
		return "", false
	}
	sort.Strings(matches)
	value := environment[matches[0]]
	for _, key := range matches {
		delete(environment, key)
	}
	environment[name] = value
	return value, true
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
