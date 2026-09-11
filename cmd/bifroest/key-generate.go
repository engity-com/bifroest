package main

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	goos "os"
	"path/filepath"

	"github.com/alecthomas/kingpin/v2"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func registerKeyGenerateCmd(parent *kingpin.CmdClause) {
	var identityFile string
	var publicFile string

	cmd := parent.Command("generate", "Generate an Ed25519 private key without replacing an existing file.").
		Action(func(*kingpin.ParseContext) error {
			return doKeyGenerate(identityFile, publicFile)
		})
	cmd.Flag("identityFile", "Private key file to create.").
		Required().
		PlaceHolder("<path>").
		StringVar(&identityFile)
	cmd.Flag("publicFile", "Optional public key file to create.").
		PlaceHolder("<path>").
		StringVar(&publicFile)
}

func doKeyGenerate(identityFile, publicFile string) error {
	if publicFile != "" {
		identityPath, err := filepath.Abs(identityFile)
		if err != nil {
			return fmt.Errorf("cannot resolve private key path %q: %w", identityFile, err)
		}
		publicPath, err := filepath.Abs(publicFile)
		if err != nil {
			return fmt.Errorf("cannot resolve public key path %q: %w", publicFile, err)
		}
		if identityPath == publicPath {
			return fmt.Errorf("private and public key files have to be different")
		}
		if _, err := goos.Lstat(publicFile); err == nil {
			return fmt.Errorf("public key file %q already exists", publicFile)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("cannot inspect public key file %q: %w", publicFile, err)
		}
	}
	key, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).CreateFile(crand.Reader, identityFile)
	if err != nil {
		return err
	}
	if publicFile == "" {
		return nil
	}
	if err := bfcrypto.WriteBootstrapFile(publicFile, bfcrypto.MarshalPublicKey(key.PublicKey()), false); err != nil {
		return fmt.Errorf("private key was created at %q but the public key cannot be written: %w", identityFile, err)
	}
	return nil
}
