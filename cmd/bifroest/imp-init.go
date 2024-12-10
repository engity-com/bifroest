package main

import (
	"io"
	goos "os"
	"path/filepath"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/sys"
)

var _ = registerCommand(func(app *kingpin.Application) {
	targetPath := imp.DefaultInitPath

	cmd := app.Command("imp-init", "Prepares the environment to run Bifröst's imp inside.").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doImpInit(targetPath)
		})
	cmd.Flag("targetPath", "Path to prepare.").
		Default(targetPath).
		PlaceHolder("<path>").
		StringVar(&targetPath)
})

func doImpInit(targetPath string) (rErr error) {
	log.WithAll(sys.VersionToMap(versionV)).
		With("targetPath", targetPath).
		Info("initialize target path for Engity's Bifröst imp...")

	self, err := goos.Executable()
	if err != nil {
		return errors.System.Newf("cannot detect own location: %w", err)
	}

	sf, err := goos.Open(self)
	if err != nil {
		return errors.System.Newf("cannot open self (%s) for reading: %w", self, err)
	}
	defer common.IgnoreCloseError(sf)

	_ = goos.MkdirAll(targetPath, 0755)
	targetFile := filepath.Join(targetPath, versionV.Os().AppendExtToFilename("bifroest"))
	tf, err := goos.OpenFile(targetFile, goos.O_CREATE|goos.O_TRUNC|goos.O_WRONLY, 0755)
	if err != nil {
		return errors.System.Newf("cannot open target file (%s) for writing: %w", targetFile, err)
	}
	defer common.KeepCloseError(&rErr, tf)

	if _, err := io.Copy(tf, sf); err != nil {
		return errors.System.Newf("cannot copy %s to %s: %w", self, targetFile, err)
	}

	return nil
}
