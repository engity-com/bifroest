package export

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/model"
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

type serverCaOpts struct {
	Flow configuration.FlowName `argument:"flowName" required:"true" description:"Flow whose active SSH certificate authority should be exported."`
}

type remoteCaOpts struct {
	serverCaOpts
	keyOutputOpts
}

func createCaCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[exportOpts]("ca", "Export the public key of a flow's SSH certificate authority.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleExport),
		cli.NewCommand[remoteCaOpts]("ca", "Export the public key of a server flow's active SSH certificate authority.").
			WithProfiles(common.ProfileRemote).
			WithHandler(func(ctx context.Context, o remoteCaOpts) error {
				return exportRemote(ctx, o.keyOutputOpts, "key", "export", "ca", o.Flow.String())
			}),
		cli.NewCommand[serverCaOpts]("ca", "Export the public key of a flow's active SSH certificate authority.").
			WithProfiles(common.ProfileManagement).
			WithHandler(func(ctx context.Context, o serverCaOpts) error {
				return exportManagement(ctx, model.KeyExportRequest{Kind: "ca", Flow: o.Flow})
			}),
	}
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
	if o.Configuration == nil {
		return nil, fmt.Errorf("configuration is unavailable")
	}
	for i := range o.Configuration.Flows {
		if o.Flow.IsEqualTo(o.Configuration.Flows[i].Name) {
			return &o.Configuration.Flows[i], nil
		}
	}
	return nil, fmt.Errorf("flow %q does not exist", o.Flow)
}
