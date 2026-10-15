package export

import (
	"context"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type publicOpts struct {
	IdentityFile string `flag:"identityFile" required:"true" placeholder:"<path>" description:"Private key file to read."`
	Comment      string `flag:"comment" placeholder:"<text>" description:"Optional public key comment."`
	Output       string `flag:"output" default:"-" placeholder:"<path|->" description:"Output file or - for stdout."`
	Force        bool   `flag:"force" description:"Replace an existing output file."`
}

func registerPublic(_ context.Context, c cli.ContainerRequirementSetters, _ common.Usage) {
	c.AddCommand(cli.NewCommand[publicOpts]().
		WithName("public").
		WithDescription("Export the public key of a local private key.").
		WithHandler(handlePublic),
	)
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
