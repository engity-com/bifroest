//go:build unix

package main

import (
	"fmt"
	goos "os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ensureExecPathEnvironment(environment map[string]string) {
	if _, exists := environment["PATH"]; exists {
		return
	}
	if path, exists := goos.LookupEnv("PATH"); exists {
		environment["PATH"] = path
	}
}

func setExecEnvironment(environment map[string]string, key, value string) {
	environment[key] = value
}

func resolveExecPath(file, workingDirectory string, environment map[string]string) (string, error) {
	if strings.ContainsRune(file, filepath.Separator) {
		return exec.LookPath(resolveTargetPath(file, workingDirectory))
	}
	for _, directory := range filepath.SplitList(environment["PATH"]) {
		candidate := resolveTargetPath(filepath.Join(directory, file), workingDirectory)
		if found, err := exec.LookPath(candidate); err == nil {
			return found, nil
		}
	}
	return "", fmt.Errorf("%s: %w", file, exec.ErrNotFound)
}

func resolveTargetPath(path, workingDirectory string) string {
	if filepath.IsAbs(path) {
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
