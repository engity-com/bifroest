package main

import (
	"fmt"
	"iter"
	gos "os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/engity-com/bifroest/pkg/common"
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

func (this *buildArtifact) toLdFlags() string {
	return this.platform.toLdFlags() +
		" " + this.buildContext.toLdFlags(this.testing)
}

func (this *buildArtifact) String() string {
	return this.platform.String() + "/" + this.t.String() + ":" + this.name()
}

func (this *buildArtifact) mediaType() string {
	switch this.t {
	case buildArtifactTypeDigest:
		return "text/plain; charset=utf-8"
	case buildArtifactTypeArchive:
		switch strings.ToLower(path.Ext(this.name())) {
		case ".tgz":
			return "application/tar+gzip"
		case ".zip":
			return "application/zip"
		default:
			return "application/octet-stream"
		}
	default:
		return "application/octet-stream"
	}
}

func (this *buildArtifact) name() string {
	return filepath.Base(this.filepath)
}

func (this *buildArtifact) Close() (rErr error) {
	this.lock.Lock()
	defer this.lock.Unlock()

	for _, closer := range this.onClose {
		//goland:noinspection GoDeferInLoop
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
		//goland:noinspection GoDeferInLoop
		defer common.KeepCloseError(&rErr, v)
	}
	return nil
}

func (this buildArtifacts) onlyOfType(t buildArtifactType) iter.Seq[*buildArtifact] {
	return this.filter(func(candidate *buildArtifact) bool {
		return candidate.t == t
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

// userOwnerAndGroupSID is a magic value needed to make the binary executable
// in a Windows container.
//
// owner: BUILTIN/Users group: BUILTIN/Users ($sddlValue="O:BUG:BU")
const windowsUserOwnerAndGroupSID = "AQAAgBQAAAAkAAAAAAAAAAAAAAABAgAAAAAABSAAAAAhAgAAAQIAAAAAAAUgAAAAIQIAAA=="
