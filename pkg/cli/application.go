package cli

import (
	"context"
	"errors"

	clibase "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

// Applications contains the two compiled, reusable command definitions. Each
// ParseAndExecute call still owns its own options, streams, and resources.
type Applications struct {
	Executable *clibase.Application[clibase.NoOptions]
	Management *clibase.Application[clibase.NoOptions]
}

func NewApplications(version sys.Version) (_ *Applications, err error) {
	result := &Applications{}
	defer func() {
		if err != nil {
			err = errors.Join(err, result.Close())
		}
	}()
	create := func(usage common.Usage) (*clibase.Application[clibase.NoOptions], error) {
		requirement := clibase.NewSimpleApplication().
			WithName("bifroest").
			WithDescription("Bifröst SSH administration.").
			WithFallbackToStdio(false).
			WithErrorHandlerEnabled(false)
		Register(context.Background(), requirement, usage, version)
		return requirement.Create()
	}
	if result.Executable, err = create(common.UsageExecutable); err != nil {
		return nil, err
	}
	if result.Management, err = create(common.UsageManagement); err != nil {
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
