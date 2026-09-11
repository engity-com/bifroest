package main

import (
	"context"
	"fmt"
	"io"
	goos "os"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

const keyImportHostNetworkTimeout = 10 * time.Second

type keyImportHostOpts struct {
	knownHostsFile      string
	input               string
	address             string
	expectedFingerprint string
}

func registerKeyImportHostCmd(parent *kingpin.CmdClause) {
	var opts keyImportHostOpts

	cmd := parent.Command("host", "Import SSH host keys from a file, stdin or a server.").
		Action(func(*kingpin.ParseContext) error {
			return doKeyImportHost(&opts, goos.Stdin)
		})
	cmd.Flag("knownHostsFile", "Known hosts file to update.").
		Required().
		PlaceHolder("<path>").
		StringVar(&opts.knownHostsFile)
	cmd.Flag("input", "Input file or - for stdin; cannot be combined with address.").
		PlaceHolder("<path|->").
		StringVar(&opts.input)
	cmd.Flag("address", "SSH server to retrieve a host key from; port defaults to 22.").
		PlaceHolder("<host[:port]>").
		StringVar(&opts.address)
	cmd.Flag("expectedFingerprint", "Expected SHA256 fingerprint or unknown.").
		PlaceHolder("<SHA256:...|unknown>").
		StringVar(&opts.expectedFingerprint)
}

func doKeyImportHost(opts *keyImportHostOpts, stdin io.Reader) error {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	if opts.address != "" && opts.input != "" {
		return fmt.Errorf("address and input cannot be combined")
	}
	expectedFingerprint := strings.TrimSpace(opts.expectedFingerprint)
	var raw []byte
	var err error
	if opts.address != "" {
		if expectedFingerprint == "" {
			return fmt.Errorf("expectedFingerprint is required with address; use unknown to explicitly accept an unverified host key")
		}
		if expectedFingerprint == "unknown" {
			log.With("address", opts.address).Warn("The host key fingerprint is unknown; trusting a key retrieved from the network is potentially unsafe")
			expectedFingerprint = ""
		}
		ctx, cancel := context.WithTimeout(context.Background(), keyImportHostNetworkTimeout)
		defer cancel()
		raw, err = bfcrypto.FetchKnownHostKey(ctx, opts.address)
	} else {
		input := opts.input
		if input == "" {
			input = "-"
		}
		raw, err = readBootstrapInput(input, stdin)
		expectedFingerprint = normalizeUnknownFingerprint(expectedFingerprint)
	}
	if err != nil {
		return err
	}
	_, err = bfcrypto.ImportKnownHostsFile(opts.knownHostsFile, raw, expectedFingerprint)
	return err
}

func normalizeUnknownFingerprint(value string) string {
	if strings.TrimSpace(value) == "unknown" {
		return ""
	}
	return strings.TrimSpace(value)
}
