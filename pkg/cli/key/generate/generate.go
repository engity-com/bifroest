package generate

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	goos "os"
	"path/filepath"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type opts struct {
	IdentityFile string `flag:"identityFile" placeholder:"<path>" required:"true" description:"Private key file to create."`
	PublicFile   string `flag:"publicFile" placeholder:"<path>" description:"Optional public key file to create."`
}

func Register(_ context.Context, c cli.ContainerRequirementSetters, usage common.Usage) {
	c.AddCommand(cli.NewCommand[opts]().
		WithName("generate").
		WithDescription("Generate an Ed25519 private key without replacing an existing file.").
		WithHandler(handle),
	)
}

func handle(_ context.Context, o opts) error {
	if o.PublicFile != "" {
		identityPath, err := filepath.Abs(o.IdentityFile)
		if err != nil {
			return fmt.Errorf("cannot resolve private key path %q: %w", o.IdentityFile, err)
		}
		publicPath, err := filepath.Abs(o.PublicFile)
		if err != nil {
			return fmt.Errorf("cannot resolve public key path %q: %w", o.PublicFile, err)
		}
		if identityPath == publicPath {
			return fmt.Errorf("private and public key files have to be different")
		}
		if _, err := goos.Lstat(o.PublicFile); err == nil {
			return fmt.Errorf("public key file %q already exists", o.PublicFile)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("cannot inspect public key file %q: %w", o.PublicFile, err)
		}
	}
	key, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).CreateFile(crand.Reader, o.IdentityFile)
	if err != nil {
		return err
	}
	if o.PublicFile == "" {
		return nil
	}
	if err := bfcrypto.WriteBootstrapFile(o.PublicFile, bfcrypto.MarshalPublicKey(key.PublicKey()), false); err != nil {
		return fmt.Errorf("private key was created at %q but the public key cannot be written: %w", o.IdentityFile, err)
	}
	return nil
}
