package main

import (
	"archive/zip"
	"compress/flate"
	"fmt"
	"io"
	gos "os"
	"time"

	"github.com/engity-com/bifroest/pkg/common"
)

func (this *buildArchive) newZipWriter(t time.Time, target io.Writer) (*buildArchiveZipWriter, error) {
	zw := zip.NewWriter(target)
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestCompression)
	})
	return &buildArchiveZipWriter{
		t,
		zw,
	}, nil
}

type buildArchiveZipWriter struct {
	time time.Time
	zip  *zip.Writer
}

func (this *buildArchiveZipWriter) Close() (rErr error) {
	defer common.KeepCloseError(&rErr, this.zip)
	return nil
}

func (this *buildArchiveZipWriter) addFile(name, sourceFn string, mode gos.FileMode) (rErr error) {
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

	header := zip.FileHeader{
		Name:               name,
		Modified:           this.time,
		UncompressedSize64: uint64(sfs.Size()),
	}
	header.SetMode(mode)
	w, err := this.zip.CreateHeader(&header)
	if err != nil {
		return fail(err)
	}

	if _, err := io.Copy(w, sf); err != nil {
		return fail(err)
	}

	return nil
}
