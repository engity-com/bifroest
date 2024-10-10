package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	gos "os"
	"time"

	"github.com/engity-com/bifroest/pkg/common"
)

func (this *buildArchive) newTgzWriter(t time.Time, target io.Writer) (*buildArchiveTgzWriter, error) {
	fail := func(err error) (*buildArchiveTgzWriter, error) {
		return nil, err
	}

	gzw, err := gzip.NewWriterLevel(target, gzip.BestCompression)
	if err != nil {
		return fail(err)
	}

	return &buildArchiveTgzWriter{
		t,
		gzw,
		tar.NewWriter(gzw),
	}, nil
}

type buildArchiveTgzWriter struct {
	time time.Time
	gzip *gzip.Writer
	tar  *tar.Writer
}

func (this *buildArchiveTgzWriter) Close() (rErr error) {
	defer common.KeepCloseError(&rErr, this.gzip)
	defer common.KeepCloseError(&rErr, this.tar)
	return nil
}

func (this *buildArchiveTgzWriter) addFile(name, sourceFn string, mode gos.FileMode) (rErr error) {
	fail := func(err error) error {
		return fmt.Errorf("cannot write file %q (source: %q): %w", name, sourceFn, err)
	}

	sf, err := gos.Open(sourceFn)
	if err != nil {
		return fail(err)
	}
	defer common.KeepCloseError(&rErr, sf)
	sfs, err := sf.Stat()
	if err != nil {
		return fail(err)
	}

	if mode == 0 {
		mode = sfs.Mode()
	}

	if err := this.tar.WriteHeader(&tar.Header{
		Typeflag:   tar.TypeReg,
		Name:       name,
		Mode:       int64(mode),
		ModTime:    this.time,
		AccessTime: this.time,
		ChangeTime: this.time,
		Size:       sfs.Size(),
	}); err != nil {
		return fail(err)
	}

	if _, err := io.Copy(this.tar, sf); err != nil {
		return fail(err)
	}

	return nil
}
