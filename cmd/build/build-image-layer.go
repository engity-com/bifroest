package main

import (
	"archive/tar"
	"fmt"
	"io"
	"iter"
	gos "os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

type imageArtifactLayerItem struct {
	sourceFile string
	targetFile string
	mode       gos.FileMode
}

func createImageArtifactLayer(os os, id string, time time.Time, items iter.Seq2[imageArtifactLayerItem, error]) (*buildImageLayer, error) {
	fail := func(err error) (*buildImageLayer, error) {
		return nil, fmt.Errorf("cannot create tar layer: %w", err)
	}

	dir := filepath.Join("var", "layers")
	_ = gos.MkdirAll(dir, 0755)

	fAlreadyClosed := false
	success := false
	f, err := gos.CreateTemp(dir, id+"-*.tar")
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreErrorIfFalse(&success, func() error { return gos.Remove(f.Name()) })
	defer common.IgnoreCloseErrorIfFalse(&fAlreadyClosed, f)

	if err := createImageArtifactLayerTar(os, time, items, f); err != nil {
		return fail(err)
	}
	common.IgnoreCloseError(f)
	fAlreadyClosed = true

	result := &buildImageLayer{
		bufferFilename: f.Name(),
	}

	if result.layer, err = tarball.LayerFromOpener(result.open); err != nil {
		return fail(err)
	}

	success = true
	return result, nil
}

func createImageArtifactLayerTar(os os, time time.Time, items iter.Seq2[imageArtifactLayerItem, error], target io.Writer) error {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(fmt.Errorf(msg, args...))
	}

	tw := tar.NewWriter(target)

	var format tar.Format
	var paxRecords map[string]string

	writeHeader := func(
		dir bool,
		name string,
		size int64,
		mode int64,
	) error {
		header := tar.Header{
			Name:       name,
			Size:       size,
			Mode:       mode,
			Format:     format,
			PAXRecords: paxRecords,
			ModTime:    time,
		}
		if dir {
			header.Typeflag = tar.TypeDir
		} else {
			header.Typeflag = tar.TypeReg
		}
		return tw.WriteHeader(&header)
	}

	adjustTargetFilename := func(v string) string {
		// Paths needs to be always relative
		if len(v) > 1 && (v[0] == '/' || v[0] == '\\') {
			v = v[1:]
		}
		return v
	}
	var dirMode int64 = 0755
	alreadyCreatedDirectories := map[string]struct{}{}

	if os == osWindows {
		dirMode = 0555
		format = tar.FormatPAX
		paxRecords = map[string]string{
			"MSWINDOWS.rawsd": windowsUserOwnerAndGroupSID,
		}

		if err := writeHeader(true, "Files", 0, dirMode); err != nil {
			return fail(err)
		}
		alreadyCreatedDirectories["Files"] = struct{}{}
		if err := writeHeader(true, "Hives", 0, dirMode); err != nil {
			return fail(err)
		}
		alreadyCreatedDirectories["Hives"] = struct{}{}

		adjustTargetFilename = func(v string) string {
			// At Windows, we need to always use /, because of the TAR format.
			// ...and they need to start always with "Files/" instead of "C:\" or similar...
			v = strings.ReplaceAll(v, "\\", "/")
			if len(v) > 3 && (v[0] == 'C' || v[0] == 'c') && v[1] == ':' && v[2] == '/' {
				v = "Files/" + v[3:]
			}
			return v
		}
	}

	addItem := func(item imageArtifactLayerItem) (rErr error) {
		f, err := gos.Open(item.sourceFile)
		if err != nil {
			return fail(err)
		}
		defer common.KeepCloseError(&rErr, f)
		fi, err := f.Stat()
		if err != nil {
			return fail(err)
		}

		targetFile := adjustTargetFilename(item.targetFile)

		var directoriesToCreate []string
		currentPath := path.Dir(targetFile)
		for currentPath != "." && currentPath != "" {
			if _, ok := alreadyCreatedDirectories[currentPath]; !ok {
				directoriesToCreate = append(directoriesToCreate, currentPath)
				alreadyCreatedDirectories[currentPath] = struct{}{}
			}
			currentPath = path.Dir(currentPath)
		}
		slices.Reverse(directoriesToCreate)
		for _, dir := range directoriesToCreate {
			if err := writeHeader(true, dir, 0, dirMode); err != nil {
				return fail(err)
			}
		}

		if err := writeHeader(false, targetFile, fi.Size(), int64(item.mode)); err != nil {
			return fail(err)
		}
		_, err = io.Copy(tw, f)

		return err
	}

	for item, err := range items {
		if err != nil {
			return fail(err)
		}

		if err := addItem(item); err != nil {
			return failf("cannot add item %q -> %q: %w", item.sourceFile, item.targetFile, err)
		}
	}

	if err := tw.Flush(); err != nil {
		return fail(err)
	}

	return nil
}

type buildImageLayer struct {
	bufferFilename string
	layer          v1.Layer
}

func (this *buildImageLayer) open() (io.ReadCloser, error) {
	return gos.Open(this.bufferFilename)
}

func (this *buildImageLayer) Close() error {
	err := gos.Remove(this.bufferFilename)
	if sys.IsNotExist(err) {
		return nil
	}
	return err
}
