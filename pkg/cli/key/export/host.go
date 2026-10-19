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

type hostOpts struct {
	configuration.EmptyStrOpts
	IdentityFile string `flag:"identityFile" placeholder:"<path>" description:"Host private key file to load or create instead of using a configuration."`
	Address      string `flag:"address" placeholder:"<host[:port]>" description:"Host represented by the host key; port defaults to 22."`
	Output       string `flag:"output" default:"-" placeholder:"<path|->" description:"Output file or - for stdout."`
	Force        bool   `flag:"force" description:"Replace an existing output file."`
}

type serverHostOpts struct {
	Address string `flag:"address" required:"true" placeholder:"<host[:port]>" description:"Host represented by the active server host keys; port defaults to 22."`
}

type remoteHostOpts struct {
	serverHostOpts
	keyOutputOpts
}

func createHostCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[hostOpts]("host", "Export SSH host keys as known_hosts entries without network access.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleHost),
		cli.NewCommand[remoteHostOpts]("host", "Export the server's active SSH host keys as known_hosts entries.").
			WithProfiles(common.ProfileRemote).
			WithHandler(func(ctx context.Context, o remoteHostOpts) error {
				return exportRemote(ctx, o.keyOutputOpts, "key", "export", "host", "--address="+o.Address)
			}),
		cli.NewCommand[serverHostOpts]("host", "Export active SSH host keys as known_hosts entries.").
			WithProfiles(common.ProfileManagement).
			WithHandler(func(ctx context.Context, o serverHostOpts) error {
				return exportManagement(ctx, model.KeyExportRequest{Kind: "host", Address: o.Address})
			}),
	}
}

func handleHost(ctx context.Context, o hostOpts) error {
	if o.Configuration != "" && o.IdentityFile != "" {
		return fmt.Errorf("configuration and identityFile cannot be combined")
	}
	var keys []bfcrypto.PrivateKey
	var identityFiles []string
	if o.IdentityFile != "" {
		key, err := bfcrypto.EnsureKeyFile(o.IdentityFile, &bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}, nil)
		if err != nil {
			return err
		}
		keys = []bfcrypto.PrivateKey{key}
		identityFiles = []string{o.IdentityFile}
	} else {
		c, _, err := o.LoadConfiguration(true)
		if err != nil {
			return err
		}
		if keys, identityFiles, err = configuration.EnsureHostPrivateKeysWithPaths(c); err != nil {
			return err
		}
	}
	if err := common.EnsureBootstrapOutputIsNotPrivateKey(o.Output, identityFiles...); err != nil {
		return err
	}
	raw, err := bfcrypto.ExportKnownHostKeys(keys, o.Address)
	if err != nil {
		return err
	}
	return common.WriteBootstrapOutput(ctx, o.Output, raw, o.Force)
}
