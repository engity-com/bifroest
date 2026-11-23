// Command generate refreshes the pinned, unmodified ConPTY interface DLLs.
package main

import (
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
	raw, err := io.ReadAll(io.LimitReader(response.Body, conpty.MaximumPackageBytes+1))
	if err != nil {
		return err
	}
	_, files, err := conpty.InspectPackage(conpty.Version, raw, conpty.PackageSHA256)
	if err != nil {
		return err
	}
	for _, payload := range conpty.Payloads {
		if err := payload.Verify(files[payload.Filename()]); err != nil {
			return err
		}
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
