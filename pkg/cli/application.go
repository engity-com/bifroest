package cli

import (
	"context"
	"errors"
	"time"

	clibase "github.com/echocat/cli4g"
	"github.com/echocat/cli4g/codec"

	managementSchema "github.com/engity-com/bifroest/pkg/cli/management"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
)

// Applications contains the two compiled, reusable command definitions. Each
// ParseAndExecute call still owns its own options, streams, and resources.
type Applications struct {
	Executable *clibase.Application[executableOptions]
	Management *clibase.Application[clibase.NoOptions]
}

func NewApplications(version sys.Version) (_ *Applications, err error) {
	result := &Applications{}
	defer func() {
		if err != nil {
			err = errors.Join(err, result.Close())
		}
	}()
	createExecutable := func() (*clibase.Application[executableOptions], error) {
		requirement := clibase.NewApplication[executableOptions]().
			WithName("bifroest").
			WithDescription("Bifröst SSH administration.").
			WithFallbackToStdio(false).
			WithErrorHandlerEnabled(false).
			WithInitializeHandler(configureExecutableLogging).
			WithCodec(configuration.NewCliCodec(true, true)).
			WithCodec(codec.NewDateTime().WithFormats(time.RFC3339), "rfc3339")
		registerExecutable(context.Background(), requirement, version)
		return requirement.Create()
	}
	if result.Executable, err = createExecutable(); err != nil {
		return nil, err
	}
	if result.Management, err = managementSchema.NewApplication(version); err != nil {
		return nil, err
	}
	return result, nil
}

func (this *Applications) Close() error {
	if this == nil {
		return nil
	}
	return errors.Join(this.Executable.Close(), this.Management.Close())
}
