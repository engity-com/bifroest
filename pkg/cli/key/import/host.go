package _import

import (
	"context"
	"fmt"
	"strings"
	"time"

	cli "github.com/echocat/cli4g"
	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

const keyImportHostNetworkTimeout = 10 * time.Second

type hostOpts struct {
	KnownHostsFile      string `flag:"knownHostsFile" placeholder:"<path>" required:"true" description:"Known hosts file to update."`
	Input               string `flag:"input" placeholder:"<path|->" description:"Input file or - for stdin; cannot be combined with address."`
	Address             string `flag:"address" placeholder:"<host[:port]>" description:"SSH server to retrieve a host key from; port defaults to 22."`
	ExpectedFingerprint string `flag:"expectedFingerprint" placeholder:"<SHA256:...|unknown>" description:"Expected SHA256 fingerprint or unknown."`
}

func createHostCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[hostOpts]("host", "Import SSH host keys from a file, stdin or a server.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleHost),
	}
}

func handleHost(ctx context.Context, o hostOpts) error {
	if o.Address != "" && o.Input != "" {
		return fmt.Errorf("address and input cannot be combined")
	}
	expectedFingerprint := strings.TrimSpace(o.ExpectedFingerprint)
	var raw []byte
	var err error
	if o.Address != "" {
		if expectedFingerprint == "" {
			return fmt.Errorf("expectedFingerprint is required with address; use unknown to explicitly accept an unverified host key")
		}
		if expectedFingerprint == "unknown" {
			log.With("address", o.Address).Warn("The host key fingerprint is unknown; trusting a key retrieved from the network is potentially unsafe")
			expectedFingerprint = ""
		}
		ctx, cancel := context.WithTimeout(ctx, keyImportHostNetworkTimeout)
		defer cancel()
		raw, err = bfcrypto.FetchKnownHostKey(ctx, o.Address)
	} else {
		input := o.Input
		if input == "" {
			input = "-"
		}
		raw, err = common.ReadBootstrapInput(ctx, input)
		expectedFingerprint = normalizeUnknownFingerprint(expectedFingerprint)
	}
	if err != nil {
		return err
	}
	_, err = bfcrypto.ImportKnownHostsFile(o.KnownHostsFile, raw, expectedFingerprint)
	return err
}

func normalizeUnknownFingerprint(value string) string {
	if strings.TrimSpace(value) == "unknown" {
		return ""
	}
	return strings.TrimSpace(value)
}
