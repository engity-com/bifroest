package _import

import (
	"context"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type caOpts struct {
	TrustedCAsFile      string `flag:"trustedCAsFile" placeholder:"<path>" required:"true" description:"Trusted SSH certificate authority file to update."`
	Input               string `flag:"input" placeholder:"<path|->" default:"-" description:"Input file or - for stdin."`
	ExpectedFingerprint string `flag:"expectedFingerprint" placeholder:"<SHA256:...|unknown>" description:"Expected SHA256 fingerprint or unknown."`
}

func createCaCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[caOpts]("ca", "Validate and atomically merge trusted SSH certificate authority keys.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleCa),
	}
}

func handleCa(ctx context.Context, o caOpts) error {
	raw, err := common.ReadBootstrapInput(ctx, o.Input)
	if err != nil {
		return err
	}
	expectedFingerprint := normalizeUnknownFingerprint(o.ExpectedFingerprint)
	_, err = bfcrypto.ImportCertificateAuthoritiesFile(o.TrustedCAsFile, raw, expectedFingerprint)
	return err
}
