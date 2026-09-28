package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/tc-hib/winres"
	winversion "github.com/tc-hib/winres/version"
)

// Generated from docs/assets/favicon.svg with transparent square padding.
//
//go:embed bifroest.ico
var windowsIcon []byte

func (this *buildBinary) addWindowsResources(binary *buildArtifact) error {
	icon, err := winres.LoadICO(bytes.NewReader(windowsIcon))
	if err != nil {
		return fmt.Errorf("cannot load Windows icon: %w", err)
	}
	source, err := os.Open(binary.filepath)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	resources, err := winres.LoadFromEXE(source)
	if errors.Is(err, winres.ErrNoResources) {
		resources = &winres.ResourceSet{}
	} else if err != nil {
		return fmt.Errorf("cannot load existing Windows resources: %w", err)
	}
	if err := resources.SetIcon(winres.ID(1), icon); err != nil {
		return err
	}

	var numeric [4]uint16
	if v := binary.version.semver; v != nil {
		if v.Major() > math.MaxUint16 || v.Minor() > math.MaxUint16 || v.Patch() > math.MaxUint16 {
			return fmt.Errorf("version %s exceeds Windows version number limits", binary.version)
		}
		numeric = [4]uint16{uint16(v.Major()), uint16(v.Minor()), uint16(v.Patch()), 0}
	}
	info := winversion.Info{FileVersion: numeric, ProductVersion: numeric, Timestamp: binary.time.UTC()}
	for _, property := range []struct{ key, value string }{
		{winversion.CompanyName, binary.vendor},
		{winversion.FileDescription, "Bifroest SSH server"},
		{winversion.FileVersion, binary.version.String()},
		{winversion.InternalName, "bifroest"},
		{winversion.OriginalFilename, "bifroest.exe"},
		{winversion.ProductName, "Bifr\u00f6st"},
		{winversion.ProductVersion, binary.version.String()},
		{winversion.Comments, "Revision: " + binary.revision},
	} {
		if err := info.Set(winres.LCIDDefault, property.key, property.value); err != nil {
			return fmt.Errorf("invalid Windows version property %s: %w", property.key, err)
		}
	}
	resources.SetVersionInfo(info)

	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	target, err := os.CreateTemp(filepath.Dir(binary.filepath), ".bifroest-resource-*.exe")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(target.Name()) }()
	stat, err := source.Stat()
	if err != nil {
		_ = target.Close()
		return err
	}
	if err := target.Chmod(stat.Mode().Perm()); err != nil {
		_ = target.Close()
		return err
	}
	writeErr := resources.WriteToEXE(target, source)
	if writeErr == nil {
		writeErr = target.Sync()
	}
	closeErr := target.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return fmt.Errorf("cannot write Windows resources: %w", err)
	}
	if err := source.Close(); err != nil {
		return err
	}
	return replaceFileAtomically(target.Name(), binary.filepath)
}
