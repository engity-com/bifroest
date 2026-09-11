package main

import (
	"fmt"
	"io"
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/service"
)

type keyExportHostOpts struct {
	configuration string
	identityFile  string
	address       string
	output        string
	force         bool
}

func registerKeyExportHostCmd(parent *kingpin.CmdClause) {
	opts := keyExportHostOpts{output: "-"}

	cmd := parent.Command("host", "Export SSH host keys as known_hosts entries without network access.").
		Action(func(*kingpin.ParseContext) error {
			return doKeyExportHost(&opts, goos.Stdout)
		})
	cmd.Flag("configuration", "Configuration to use when identityFile is absent. Default: "+defaultConfigurationRef).
		Short('c').
		PlaceHolder("<path>").
		StringVar(&opts.configuration)
	cmd.Flag("identityFile", "Host private key file to load or create instead of using a configuration.").
		PlaceHolder("<path>").
		StringVar(&opts.identityFile)
	cmd.Flag("address", "Host represented by the host key; port defaults to 22.").
		Required().
		PlaceHolder("<host[:port]>").
		StringVar(&opts.address)
	cmd.Flag("output", "Output file or - for stdout.").
		Default(opts.output).
		PlaceHolder("<path|->").
		StringVar(&opts.output)
	cmd.Flag("force", "Replace an existing output file.").
		BoolVar(&opts.force)
}

func doKeyExportHost(opts *keyExportHostOpts, stdout io.Writer) error {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	if opts.configuration != "" && opts.identityFile != "" {
		return fmt.Errorf("configuration and identityFile cannot be combined")
	}
	var keys []bfcrypto.PrivateKey
	var identityFiles []string
	if opts.identityFile != "" {
		key, err := bfcrypto.EnsureKeyFile(opts.identityFile, &bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}, nil)
		if err != nil {
			return err
		}
		keys = []bfcrypto.PrivateKey{key}
		identityFiles = []string{opts.identityFile}
	} else {
		configurationFile := opts.configuration
		if configurationFile == "" {
			configurationFile = defaultConfigurationRef
		}
		var ref configuration.Ref
		if err := ref.Set(configurationFile); err != nil {
			return err
		}
		var err error
		if keys, identityFiles, err = service.EnsureHostPrivateKeysWithPaths(ref.Get()); err != nil {
			return err
		}
	}
	if err := ensureBootstrapOutputIsNotPrivateKey(opts.output, identityFiles...); err != nil {
		return err
	}
	raw, err := bfcrypto.ExportKnownHostKeys(keys, opts.address)
	if err != nil {
		return err
	}
	return writeBootstrapOutput(opts.output, raw, opts.force, stdout)
}
