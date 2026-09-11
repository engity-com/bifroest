package main

import (
	"io"
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func registerKeyExportPublicCmd(parent *kingpin.CmdClause) {
	var identityFile string
	var comment string
	output := "-"
	var force bool

	cmd := parent.Command("public", "Export the public key of a local private key.").
		Action(func(*kingpin.ParseContext) error {
			return doKeyExportPublic(identityFile, comment, output, force, goos.Stdout)
		})
	cmd.Flag("identityFile", "Private key file to read.").
		Required().
		PlaceHolder("<path>").
		StringVar(&identityFile)
	cmd.Flag("comment", "Optional public key comment.").
		PlaceHolder("<text>").
		StringVar(&comment)
	cmd.Flag("output", "Output file or - for stdout.").
		Default(output).
		PlaceHolder("<path|->").
		StringVar(&output)
	cmd.Flag("force", "Replace an existing output file.").
		BoolVar(&force)
}

func doKeyExportPublic(identityFile, comment, output string, force bool, stdout io.Writer) error {
	if err := ensureBootstrapOutputIsNotPrivateKey(output, identityFile); err != nil {
		return err
	}
	raw, err := bfcrypto.ExportPublicKey(identityFile, comment)
	if err != nil {
		return err
	}
	return writeBootstrapOutput(output, raw, force, stdout)
}
