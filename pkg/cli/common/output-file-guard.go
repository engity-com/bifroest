package common

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/sys"
)

type fileOutputGuard struct {
	path  string
	info  fs.FileInfo
	label string
}

func newFileOutputGuard(output string, stdout io.Writer) (*fileOutputGuard, error) {
	if output == "" || output == "-" {
		file, ok := stdout.(*os.File)
		if !ok {
			return nil, nil
		}
		info, err := file.Stat()
		if err != nil {
			return nil, fmt.Errorf("cannot inspect standard output: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, nil
		}
		return &fileOutputGuard{info: info, label: "standard output"}, nil
	}
	path, err := sys.CanonicalPath(output)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve output path %q: %w", output, err)
	}
	info, err := os.Stat(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("cannot inspect output path %q: %w", output, err)
	}
	return &fileOutputGuard{path: path, info: info, label: fmt.Sprintf("output %q", output)}, nil
}

func (this *fileOutputGuard) check(ctx context.Context, path, description string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if path == "" {
		return nil
	}
	if this.path != "" {
		canonical, err := sys.CanonicalPath(path)
		if err != nil {
			return fmt.Errorf("cannot resolve %s %q: %w", description, path, err)
		}
		// Rel also applies the platform's path comparison, including Windows case folding.
		relative, err := filepath.Rel(this.path, canonical)
		if err == nil && relative == "." {
			return fmt.Errorf("%s must not replace %s %q", this.label, description, path)
		}
	}
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot inspect %s %q: %w", description, path, err)
	}
	if this.info != nil && os.SameFile(this.info, info) {
		return fmt.Errorf("%s must not replace %s %q", this.label, description, path)
	}
	return nil
}
