package main

import (
	"debug/buildinfo"
	"fmt"
	osexec "os/exec"
)

func verifiedGoTool(name, module, version string) (string, error) {
	filename, err := osexec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("cannot find required tool %q: %w", name, err)
	}
	info, err := buildinfo.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("cannot inspect required tool %q: %w", filename, err)
	}
	if info.Main.Path != module || info.Main.Version != version {
		return "", fmt.Errorf("required tool %q is %s %s instead of %s %s", filename, info.Main.Path, info.Main.Version, module, version)
	}
	return filename, nil
}
