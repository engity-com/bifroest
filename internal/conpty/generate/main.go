// Command generate refreshes the pinned, unmodified ConPTY interface DLLs.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/engity-com/bifroest/internal/conpty"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	client := &http.Client{Timeout: time.Minute}
	response, err := client.Get(conpty.PackageURL)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("ConPTY package download: HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != conpty.PackageSHA256 {
		return fmt.Errorf("ConPTY package digest mismatch")
	}
	archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return err
	}
	files := make(map[string][]byte)
	for _, payload := range conpty.Payloads {
		file, err := archive.Open(payload.Source)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(file, 2<<20))
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err := payload.Verify(data); err != nil {
			return err
		}
		files[payload.Filename()] = data
	}
	for name, data := range files {
		if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(name, data, 0644); err != nil {
			return err
		}
	}
	return nil
}
