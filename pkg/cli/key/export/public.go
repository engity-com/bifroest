package export

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type publicOpts struct {
	IdentityFile string `flag:"identityFile" required:"true" placeholder:"<path>" description:"Private key file to read."`
	Comment      string `flag:"comment" placeholder:"<text>" description:"Optional public key comment."`
	Output       string `flag:"output" default:"-" placeholder:"<path|->" description:"Output file or - for stdout."`
	Force        bool   `flag:"force" description:"Replace an existing output file."`
}

type serverPublicOpts struct {
	Flow          configuration.FlowName `argument:"flowName" required:"true" description:"Flow whose configured SSH identity should be exported."`
	IdentityIndex uint                   `flag:"identityIndex" default:"0" description:"Zero-based index in the flow's configured SSH identity files; certificate identity uses 0."`
	Comment       string                 `flag:"comment" placeholder:"<text>" description:"Optional public key comment."`
}

type remotePublicOpts struct {
	serverPublicOpts
	keyOutputOpts
}

func createPublicCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[publicOpts]("public", "Export the public key of a local private key.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handlePublic),
		cli.NewCommand[remotePublicOpts]("public", "Export a configured server SSH identity's public key.").
			WithProfiles(common.ProfileRemote).
			WithHandler(func(ctx context.Context, o remotePublicOpts) error {
				return exportRemote(ctx, o.keyOutputOpts, "key", "export", "public", o.Flow.String(), fmt.Sprintf("--identityIndex=%d", o.IdentityIndex), "--comment="+o.Comment)
			}),
		cli.NewCommand[serverPublicOpts]("public", "Export a configured SSH identity's public key.").
			WithProfiles(common.ProfileManagement).
			WithHandler(func(ctx context.Context, o serverPublicOpts) error {
				return exportManagement(ctx, model.KeyExportRequest{Kind: "public", Flow: o.Flow, IdentityIndex: o.IdentityIndex, Comment: o.Comment})
			}),
	}
}

func handlePublic(ctx context.Context, o publicOpts) error {
	if err := common.EnsureBootstrapOutputIsNotPrivateKey(o.Output, o.IdentityFile); err != nil {
		return err
	}
	raw, err := bfcrypto.ExportPublicKey(o.IdentityFile, o.Comment)
	if err != nil {
		return err
	}
	return common.WriteBootstrapOutput(ctx, o.Output, raw, o.Force)
}
