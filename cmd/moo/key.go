package main

import (
	crand "crypto/rand"
	"encoding/pem"
	"fmt"
	gssh "github.com/gliderlabs/ssh"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"path/filepath"
)

func hostKey(rand io.Reader, privateKeyFn string) gssh.Option {
	return func(srv *gssh.Server) error {
		signer, err := ensurePrivateKey(rand, privateKeyFn)
		if err != nil {
			return err
		}

		srv.AddHostKey(signer)

		return nil
	}
}

func generateEd25519Key(rand io.Reader) (ed25519.PrivateKey, error) {
	if rand == nil {
		rand = crand.Reader
	}
	_, prv, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	return prv, err
}

func createNewPrivateKey(rand io.Reader, privateKeyFile string) (ssh.Signer, error) {
	key, err := generateEd25519Key(rand)
	if err != nil {
		return nil, fmt.Errorf("cannot generate new key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("cannot convert new gerneted key to ssh.Signer: %w", err)
	}

	_ = os.MkdirAll(filepath.Dir(privateKeyFile), 0700)
	f, err := os.OpenFile(privateKeyFile, os.O_CREATE|os.O_WRONLY, 0400)
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, &pem.Block{
		Type:    "OPENSSH PRIVATE KEY",
		Headers: nil,
		Bytes:   edkey.MarshalED25519PrivateKey(key),
	}); err != nil {
		return nil, fmt.Errorf("cannot write new generated key %q: %w", privateKeyFile, err)
	}

	return signer, nil
}

func ensurePrivateKey(rand io.Reader, privateKeyFile string) (ssh.Signer, error) {
	raw, err := os.ReadFile(privateKeyFile)
	if os.IsNotExist(err) {
		return createNewPrivateKey(rand, privateKeyFile)
	} else if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", privateKeyFile, err)
	}

	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("cannot parse %q: %w", privateKeyFile, err)
	}

	return signer, nil
}

func ensureAuthorizedKeys(failOnMissing bool, files ...string) (map[string]struct{}, error) {
	result := map[string]struct{}{}

	for _, file := range files {
		bytes, err := os.ReadFile("var/authorized_keys")
		if os.IsNotExist(err) {
			if failOnMissing {
				return nil, fmt.Errorf("authorized key file %q does not exist", file)
			}
		} else if err != nil {
			return nil, fmt.Errorf("cannot read authorized key file %q: %w", file, err)
		}

		for len(bytes) > 0 {
			pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(bytes)
			if err != nil {
				return nil, fmt.Errorf("cannot parse authorized key file %q: %w", file, err)
			}
			result[string(pubKey.Marshal())] = struct{}{}
			bytes = rest
		}
	}

	return result, nil
}
