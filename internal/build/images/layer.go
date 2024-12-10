package images

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"iter"
	gos "os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type LayerOpts struct {
	Os   sys.Os
	Id   string
	Time time.Time
}

func NewTarLayer(from iter.Seq2[LayerItem, error], opts LayerOpts) (*BufferedLayer, error) {
	fail := func(err error) (*BufferedLayer, error) {
		return nil, errors.System.Newf("cannot create tar layer: %w", err)
	}
	failf := func(msg string, args ...any) (*BufferedLayer, error) {
		return fail(errors.System.Newf(msg, args...))
	}

	dir := filepath.Join("var", "layers")
	_ = gos.MkdirAll(dir, 0755)

	if opts.Os.IsZero() {
		return failf("no os provided")
	}
	if opts.Id == "" {
		u, err := uuid.NewUUID()
		if err != nil {
			return fail(err)
		}
		opts.Id = u.String()
	}
	if opts.Time.IsZero() {
		opts.Time = time.Now()
	}

	fAlreadyClosed := false
	success := false
	f, err := gos.CreateTemp(dir, opts.Id+"-*.tar")
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreErrorIfFalse(&success, func() error { return gos.Remove(f.Name()) })
	defer common.IgnoreCloseErrorIfFalse(&fAlreadyClosed, f)

	if err := createImageArtifactLayerTar(&opts, from, f); err != nil {
		return fail(err)
	}
	common.IgnoreCloseError(f)
	fAlreadyClosed = true

	result := &BufferedLayer{
		bufferFilename: f.Name(),
	}

	if result.Layer, err = tarball.LayerFromOpener(result.open); err != nil {
		return fail(err)
	}

	success = true
	return result, nil
}

func createImageArtifactLayerTar(opts *LayerOpts, items iter.Seq2[LayerItem, error], target io.Writer) error {
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
			ModTime:    opts.Time,
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

	if opts.Os == sys.OsWindows {
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

	addItem := func(item LayerItem) (rErr error) {
		var f fs.File
		var err error
		if v := item.SourceFs; v != nil {
			f, err = v.Open(item.SourceFile)
		} else {
			f, err = gos.Open(item.SourceFile)
		}
		if err != nil {
			return fail(err)
		}
		defer common.KeepCloseError(&rErr, f)
		fi, err := f.Stat()
		if err != nil {
			return fail(err)
		}

		targetFile := adjustTargetFilename(item.TargetFile)

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

		if err := writeHeader(false, targetFile, fi.Size(), int64(item.Mode)); err != nil {
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
			return failf("cannot add item %q -> %q: %w", item.SourceFile, item.TargetFile, err)
		}
	}

	if err := tw.Flush(); err != nil {
		return fail(err)
	}

	return nil
}

type BufferedLayer struct {
	bufferFilename string
	Layer          v1.Layer
}

func (this *BufferedLayer) open() (io.ReadCloser, error) {
	return gos.Open(this.bufferFilename)
}

func (this *BufferedLayer) Close() error {
	err := gos.Remove(this.bufferFilename)
	if sys.IsNotExist(err) {
		return nil
	}
	return err
}

// userOwnerAndGroupSID is a magic value needed to make the binary executable
// in a Windows container.
//
// owner: BUILTIN/Users group: BUILTIN/Users ($sddlValue="O:BUG:BU")
const windowsUserOwnerAndGroupSID = "AQAAgBQAAAAkAAAAAAAAAAAAAAABAgAAAAAABSAAAAAhAgAAAQIAAAAAAAUgAAAAIQIAAA=="
