package export

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
)

type exportOpts struct {
	configuration.Opts
	Output string                 `flag:"output" default:"-" placeholder:"<path|->" description:"Output file or - for stdout."`
	Force  bool                   `flag:"force" description:"Replace an existing output file."`
	Flow   configuration.FlowName `argument:"flowName" required:"true" description:"Flow whose SSH certificate authority should be exported."`
}

func registerCa(_ context.Context, c cli.ContainerRequirementSetters, _ common.Usage) {
	c.AddCommand(cli.NewCommand[exportOpts]().
		WithName("ca").
		WithDescription("Export the public key of a flow's SSH certificate authority.").
		WithHandler(handleExport),
	)
}

func handleExport(ctx context.Context, o exportOpts) error {
	flow, err := findConfiguredFlow(&o)
	if err != nil {
		return err
	}
	key, identityFile, err := environment.EnsureSshCertificateAuthority(flow)
	if err != nil {
		return err
	}
	if err := common.EnsureBootstrapOutputIsNotPrivateKey(o.Output, identityFile); err != nil {
		return err
	}
	return common.WriteBootstrapOutput(ctx, o.Output, bfcrypto.MarshalPublicKey(key.PublicKey()), o.Force)
}

func findConfiguredFlow(o *exportOpts) (*configuration.Flow, error) {
	for i := range o.Configuration.Flows {
		if o.Flow.IsEqualTo(o.Configuration.Flows[i].Name) {
			return &o.Configuration.Flows[i], nil
		}
	}
	return nil, fmt.Errorf("flow %q does not exist", o.Flow)
}
