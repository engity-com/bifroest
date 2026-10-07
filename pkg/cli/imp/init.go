package imp

import (
	"context"
	"io"
	goos "os"
	"path/filepath"

	cli "github.com/echocat/cli4g"
	log "github.com/echocat/slf4g"

	. "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/sys"
)

type initOpts struct {
	TargetPath string `flag:"targetPath" placeholder:"<path>" description:"Path to prepare."`
}

func newInitOpts(context.Context) (initOpts, error) {
	return initOpts{
		imp.DefaultInitPath,
	}, nil
}

func registerInit(_ context.Context, c cli.ContainerRequirementSetters, usage Usage, version sys.Version) {
	if !usage.IncludeService() {
		return
	}

	c.AddCommand(cli.NewCommand[initOpts]().
		WithName("imp-init").
		WithDescription("Prepares the environment to run Bifröst's imp inside.").
		WithVisible(false).
		WithCreateOptionsHandler(newInitOpts).
		WithHandler(func(ctx context.Context, o initOpts) error {
			return handleInit(ctx, o, version)
		}),
	)
}

func handleInit(_ context.Context, o initOpts, version sys.Version) (rErr error) {
	log.WithAll(sys.VersionToMap(version)).
		With("targetPath", o.TargetPath).
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

	_ = goos.MkdirAll(o.TargetPath, 0755)
	targetFile := filepath.Join(o.TargetPath, version.Os().AppendExtToFilename("bifroest"))
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
