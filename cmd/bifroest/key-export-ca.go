package main

import (
	"fmt"
	"io"
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
)

type keyExportCaOpts struct {
	configuration configuration.Ref
	flow          configuration.FlowName
	output        string
	force         bool
}

func registerKeyExportCaCmd(parent *kingpin.CmdClause) {
	opts := keyExportCaOpts{output: "-"}

	cmd := parent.Command("ca", "Export the public key of a flow's SSH certificate authority.").
		Action(func(*kingpin.ParseContext) error {
			return doKeyExportCa(&opts, goos.Stdout)
		})
	registerConfigurationFlag(cmd, &opts.configuration)
	cmd.Flag("output", "Output file or - for stdout.").
		Default(opts.output).
		PlaceHolder("<path|->").
		StringVar(&opts.output)
	cmd.Flag("force", "Replace an existing output file.").
		BoolVar(&opts.force)
	cmd.Arg("flowName", "Flow whose SSH certificate authority should be exported.").
		Required().
		SetValue(&opts.flow)
}

func doKeyExportCa(opts *keyExportCaOpts, stdout io.Writer) error {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	flow, err := findConfiguredFlow(opts.configuration.Get(), opts.flow)
	if err != nil {
		return err
	}
	key, identityFile, err := environment.EnsureSshCertificateAuthority(flow)
	if err != nil {
		return err
	}
	if err := ensureBootstrapOutputIsNotPrivateKey(opts.output, identityFile); err != nil {
		return err
	}
	return writeBootstrapOutput(opts.output, bfcrypto.MarshalPublicKey(key.PublicKey()), opts.force, stdout)
}

func findConfiguredFlow(conf *configuration.Configuration, name configuration.FlowName) (*configuration.Flow, error) {
	if conf == nil {
		return nil, fmt.Errorf("nil configuration")
	}
	for i := range conf.Flows {
		if conf.Flows[i].Name == name {
			return &conf.Flows[i], nil
		}
	}
	return nil, fmt.Errorf("flow %q does not exist", name)
}
