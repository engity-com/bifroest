package main

import (
	"fmt"
	"io/fs"
	gos "os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/engity-com/bifroest/internal/build/images"
	"github.com/engity-com/bifroest/pkg/sys"
)

type releaseLicenseFile struct {
	source string
	name   string
}

func releaseLicenseFiles(root string) ([]releaseLicenseFile, error) {
	add := func(result []releaseLicenseFile, source string, info fs.FileInfo) ([]releaseLicenseFile, error) {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("release license %q is not a regular file", source)
		}
		name, err := filepath.Rel(root, source)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve release license %q: %w", source, err)
		}
		return append(result, releaseLicenseFile{
			source: source,
			name:   filepath.ToSlash(name),
		}), nil
	}

	license := filepath.Join(root, "LICENSE")
	info, err := gos.Stat(license)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect release license %q: %w", license, err)
	}
	result, err := add(nil, license, info)
	if err != nil {
		return nil, err
	}

	licenses := filepath.Join(root, "LICENSES")
	err = filepath.WalkDir(licenses, func(source string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		result, err = add(result, source, info)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("cannot collect release licenses from %q: %w", licenses, err)
	}
	if len(result) == 1 {
		return nil, fmt.Errorf("release license directory %q contains no files", licenses)
	}
	slices.SortFunc(result, func(a, b releaseLicenseFile) int { return strings.Compare(a.name, b.name) })
	return result, nil
}

func addReleaseLicensesToArchive(root string, target buildArchiveWriter) error {
	licenses, err := releaseLicenseFiles(root)
	if err != nil {
		return err
	}
	for _, license := range licenses {
		if err := target.addFile(license.name, license.source, 0644); err != nil {
			return fmt.Errorf("cannot add release license %q: %w", license.name, err)
		}
	}
	return nil
}

func releaseLicenseImageItems(root string, targetOs sys.Os) ([]images.LayerItem, error) {
	licenses, err := releaseLicenseFiles(root)
	if err != nil {
		return nil, err
	}
	result := make([]images.LayerItem, 0, len(licenses))
	for _, license := range licenses {
		var target string
		switch targetOs {
		case sys.OsLinux:
			target = path.Join("/usr/share/licenses/bifroest", license.name)
		case sys.OsWindows:
			target = `C:\Program Files\Engity\Bifroest\` + strings.ReplaceAll(license.name, "/", `\`)
		default:
			return nil, fmt.Errorf("cannot resolve release license location for os %v", targetOs)
		}
		result = append(result, images.LayerItem{
			SourceFile: license.source,
			TargetFile: target,
			Mode:       0644,
		})
	}
	return result, nil
}
