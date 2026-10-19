package management

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/engity-com/bifroest/pkg/sys"
)

// EnsureOutputSafe protects the login identities and host trust files used by
// this target, for both stdout and an explicitly named export destination.
func (target Target) EnsureOutputSafe(ctx context.Context, destination string, output io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	conf, err := resolve(target)
	if err != nil {
		return err
	}
	return ensureSSHInputOutputSafe(ctx, conf, destination, output)
}

func ensureSSHInputOutputSafe(ctx context.Context, conf settings, destination string, output io.Writer) error {
	var outputInfo fs.FileInfo
	var outputPath string
	if destination == "" || destination == "-" {
		file, ok := output.(*os.File)
		if !ok {
			return nil
		}
		var err error
		outputInfo, err = file.Stat()
		if err != nil {
			return fmt.Errorf("cannot inspect management output: %w", err)
		}
		if !outputInfo.Mode().IsRegular() {
			return nil
		}
	} else {
		var err error
		outputPath, err = sys.CanonicalPath(destination)
		if err != nil {
			return err
		}
		outputInfo, err = os.Stat(outputPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	check := func(path, description string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		path, err := expandHome(path)
		if err != nil {
			return err
		}
		canonical, err := sys.CanonicalPath(path)
		if err != nil {
			return err
		}
		if outputPath != "" && canonical == outputPath {
			return fmt.Errorf("management output must not replace %s %q", description, path)
		}
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("cannot inspect %s %q: %w", description, path, err)
		}
		if outputInfo != nil && os.SameFile(outputInfo, info) {
			return fmt.Errorf("management output must not replace %s %q", description, path)
		}
		return nil
	}
	if conf.configuration != "" {
		if err := check(conf.configuration, "SSH client configuration"); err != nil {
			return err
		}
	}
	for _, identity := range conf.identities {
		if err := check(identity, "SSH login identity"); err != nil {
			return err
		}
	}
	for _, hosts := range conf.knownHosts {
		if err := check(hosts, "SSH known-hosts file"); err != nil {
			return err
		}
	}
	return nil
}
