package main

import (
	"io"
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func registerKeyImportCaCmd(parent *kingpin.CmdClause) {
	var trustedCAsFile string
	input := "-"
	var expectedFingerprint string

	cmd := parent.Command("ca", "Validate and atomically merge trusted SSH certificate authority keys.").
		Action(func(*kingpin.ParseContext) error {
			return doKeyImportCa(trustedCAsFile, input, expectedFingerprint, goos.Stdin)
		})
	cmd.Flag("trustedCAsFile", "Trusted SSH certificate authority file to update.").
		Required().
		PlaceHolder("<path>").
		StringVar(&trustedCAsFile)
	cmd.Flag("input", "Input file or - for stdin.").
		Default(input).
		PlaceHolder("<path|->").
		StringVar(&input)
	cmd.Flag("expectedFingerprint", "Expected SHA256 fingerprint or unknown.").
		PlaceHolder("<SHA256:...|unknown>").
		StringVar(&expectedFingerprint)
}

func doKeyImportCa(trustedCAsFile, input, expectedFingerprint string, stdin io.Reader) error {
	raw, err := readBootstrapInput(input, stdin)
	if err != nil {
		return err
	}
	expectedFingerprint = normalizeUnknownFingerprint(expectedFingerprint)
	_, err = bfcrypto.ImportCertificateAuthoritiesFile(trustedCAsFile, raw, expectedFingerprint)
	return err
}
