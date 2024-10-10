package main

import (
	"archive/tar"
	"fmt"
	"io"
	"iter"
	gos "os"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
)

type buildArtifactCloser func() error

type buildArtifact struct {
	*platform
	*buildContext

	t        buildArtifactType
	filepath string
	ociImage v1.Image
	ociIndex v1.ImageIndex

	onClose []buildArtifactCloser
	lock    sync.Mutex
}

func (this *buildArtifact) toLdFlags(o os) string {
	return this.platform.toLdFlags(o) +
		" " + this.buildContext.toLdFlags(this.testing)
}

func (this *buildArtifact) String() string {
	return this.platform.String() + "/" + this.t.String() + ":" + this.filepath
}

func (this *buildArtifact) Close() (rErr error) {
	this.lock.Lock()
	defer this.lock.Unlock()

	for _, closer := range this.onClose {
		defer common.KeepError(&rErr, closer)
	}

	return nil
}

func (this *buildArtifact) addCloser(v buildArtifactCloser) {
	this.lock.Lock()
	defer this.lock.Unlock()

	this.onClose = append(this.onClose, v)
}

type buildArtifactType uint8

const (
	buildArtifactTypeBinary buildArtifactType = iota
	buildArtifactTypeArchive
	buildArtifactTypeImagePlatform
	buildArtifactTypeImage
	buildArtifactTypeDigest
)

func (this buildArtifactType) String() string {
	v, ok := buildArtifactTypeToString[this]
	if !ok {
		return fmt.Sprintf("illegal-build-artifact-type-%d", this)
	}
	return v
}

func (this buildArtifactType) canBePublished() bool {
	switch this {
	case buildArtifactTypeArchive, buildArtifactTypeDigest:
		return true
	default:
		return false
	}
}

var (
	buildArtifactTypeToString = map[buildArtifactType]string{
		buildArtifactTypeBinary:        "binary",
		buildArtifactTypeArchive:       "archive",
		buildArtifactTypeImagePlatform: "imagePlatform",
		buildArtifactTypeImage:         "image",
		buildArtifactTypeDigest:        "digest",
	}
)

type buildArtifacts []*buildArtifact

func (this buildArtifacts) Close() (rErr error) {
	for _, v := range this {
		defer common.KeepCloseError(&rErr, v)
	}
	return nil
}

func (this buildArtifacts) onlyOfType(t buildArtifactType) iter.Seq[*buildArtifact] {
	return this.filter(func(candidate *buildArtifact) bool {
		return candidate.t == t
	})
}

func (this buildArtifacts) onlyOfEdition(e edition) iter.Seq[*buildArtifact] {
	return this.filter(func(candidate *buildArtifact) bool {
		return candidate.edition == e
	})
}

func (this buildArtifacts) withoutType(t buildArtifactType) iter.Seq[*buildArtifact] {
	return this.filter(func(candidate *buildArtifact) bool {
		return candidate.t != t
	})
}

func (this buildArtifacts) filter(predicate func(*buildArtifact) bool) iter.Seq[*buildArtifact] {
	return func(yield func(*buildArtifact) bool) {
		for _, candidate := range this {
			if predicate(candidate) && !yield(candidate) {
				return
			}
		}
	}
}

func (this *buildArtifact) openFile() (*gos.File, error) {
	if this.filepath == "" {
		return nil, fmt.Errorf("cannot open file of non-file artifact: %v", this)
	}

	return gos.Open(this.filepath)
}

func (this *buildArtifact) createFile() (*gos.File, error) {
	if this.filepath == "" {
		return nil, fmt.Errorf("cannot create file of non-file artifact: %v", this)
	}

	return gos.OpenFile(this.filepath, gos.O_CREATE|gos.O_TRUNC|gos.O_WRONLY, 0644)
}

func (this *buildArtifact) toLayer(otherItems iter.Seq2[imageArtifactLayerItem, error]) (v1.Layer, error) {
	if this.t != buildArtifactTypeBinary {
		return nil, fmt.Errorf("cannot create layer of non-binary artifact: %v", this)
	}

	items := common.JoinSeq2[imageArtifactLayerItem, error](
		common.SingleSeq2Of[imageArtifactLayerItem, error](imageArtifactLayerItem{
			sourceFile: this.filepath,
			targetFile: this.platform.os.bifroestBinaryFilePath(),
			mode:       755,
		}, nil),
		otherItems,
	)

	success := false
	result, err := createImageArtifactLayer(
		this.os,
		strings.ReplaceAll(this.platform.String()+"-"+this.t.String(), "/", "-"),
		this.time,
		items,
	)
	if err != nil {
		return nil, err
	}
	defer common.IgnoreCloseErrorIfFalse(&success, result)

	this.addCloser(result.Close)

	success = true
	return result.layer, nil
}

func (this *buildArtifact) toTarReader(configFilename string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		success := false
		pr, pw := io.Pipe()
		result := &buildArtifactTarReader{owner: this, pr: pr, pw: pw}
		defer common.IgnoreErrorIfFalse(&success, result.Close)

		bf, err := this.openFile()
		if err != nil {
			return nil, err
		}
		defer common.IgnoreErrorIfFalse(&success, bf.Close)

		bfi, err := bf.Stat()
		if err != nil {
			return nil, err
		}

		cf, err := gos.Open(configFilename)
		if err != nil {
			return nil, err
		}
		defer common.IgnoreErrorIfFalse(&success, cf.Close)

		cfi, err := cf.Stat()
		if err != nil {
			return nil, err
		}

		adjustPath := func(in string) string {
			// Also at Windows we need to always use /, because of the TAR format.
			// The OCI runtime will fix this back to \ at execution.
			in = strings.ReplaceAll(in, "\\", "/")
			if len(in) > 3 && (in[0] == 'C' || in[0] == 'c') && in[1] == ':' && in[2] == '/' {
				in = "Files/" + in[3:]
			}
			return in
		}

		go func() {
			tw := tar.NewWriter(pw)
			defer common.IgnoreCloseError(tw)

			var format tar.Format
			var paxRecords map[string]string

			if this.platform.os == osWindows {
				format = tar.FormatPAX
				paxRecords = map[string]string{
					"MSWINDOWS.rawsd": windowsUserOwnerAndGroupSID,
				}

				if err := tw.WriteHeader(&tar.Header{
					Typeflag:   tar.TypeDir,
					Name:       "Files",
					Size:       bfi.Size(),
					Mode:       0555,
					Format:     format,
					PAXRecords: paxRecords,
					ModTime:    this.time,
				}); err != nil {
					_ = pw.CloseWithError(err)
					return
				}
				if err := tw.WriteHeader(&tar.Header{
					Typeflag:   tar.TypeDir,
					Name:       "Hives",
					Size:       bfi.Size(),
					Mode:       0555,
					Format:     format,
					PAXRecords: paxRecords,
					ModTime:    this.time,
				}); err != nil {
					_ = pw.CloseWithError(err)
					return
				}
			}

			if err := tw.WriteHeader(&tar.Header{
				Typeflag:   tar.TypeReg,
				Name:       adjustPath(this.platform.os.bifroestBinaryFilePath()),
				Size:       bfi.Size(),
				Mode:       0755,
				Format:     format,
				PAXRecords: paxRecords,
				ModTime:    this.time,
			}); err != nil {
				_ = pw.CloseWithError(err)
				return
			}

			if _, err := io.Copy(tw, bf); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				_ = pw.CloseWithError(err)
				return
			}

			if err := tw.WriteHeader(&tar.Header{
				Typeflag:   tar.TypeReg,
				Name:       adjustPath(this.platform.os.bifroestConfigFilePath()),
				Size:       cfi.Size(),
				Mode:       0644,
				Format:     format,
				PAXRecords: paxRecords,
				ModTime:    this.time,
			}); err != nil {
				_ = pw.CloseWithError(err)
				return
			}

			if _, err := io.Copy(tw, cf); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				_ = pw.CloseWithError(err)
				return
			}

			_ = pw.CloseWithError(nil)
		}()

		success = true
		return result, nil

	}
}

type buildArtifactTarReader struct {
	owner *buildArtifact
	pr    *io.PipeReader
	pw    *io.PipeWriter
}

func (this *buildArtifactTarReader) Read(p []byte) (n int, err error) {
	return this.pr.Read(p)
}

func (this *buildArtifactTarReader) Close() (rErr error) {
	defer common.KeepCloseError(&rErr, this.pr)
	defer common.KeepCloseError(&rErr, this.pw)
	return nil
}

// userOwnerAndGroupSID is a magic value needed to make the binary executable
// in a Windows container.
//
// owner: BUILTIN/Users group: BUILTIN/Users ($sddlValue="O:BUG:BU")
const windowsUserOwnerAndGroupSID = "AQAAgBQAAAAkAAAAAAAAAAAAAAABAgAAAAAABSAAAAAhAgAAAQIAAAAAAAUgAAAAIQIAAA=="
