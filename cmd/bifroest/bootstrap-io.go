package main

import (
	"fmt"
	"io"
	goos "os"
	"path/filepath"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func readBootstrapInput(path string, stdin io.Reader) ([]byte, error) {
	var reader io.Reader
	var closeInput io.Closer
	if path == "-" {
		reader = stdin
	} else {
		file, err := goos.Open(path)
		if err != nil {
			return nil, fmt.Errorf("cannot open input file %q: %w", path, err)
		}
		reader, closeInput = file, file
	}
	if closeInput != nil {
		defer closeInput.Close()
	}
	raw, err := io.ReadAll(io.LimitReader(reader, bfcrypto.MaxBootstrapInputSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read input: %w", err)
	}
	if len(raw) > bfcrypto.MaxBootstrapInputSize {
		return nil, fmt.Errorf("input exceeds %d bytes", bfcrypto.MaxBootstrapInputSize)
	}
	return raw, nil
}

func writeBootstrapOutput(path string, raw []byte, force bool, stdout io.Writer) error {
	if path == "-" {
		_, err := stdout.Write(raw)
		return err
	}
	return bfcrypto.WriteBootstrapFile(path, raw, force)
}

func ensureBootstrapOutputIsNotPrivateKey(output string, privateKeys ...string) error {
	if output == "-" {
		return nil
	}
	outputPath, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("cannot resolve output path %q: %w", output, err)
	}
	outputInfo, outputInfoErr := goos.Stat(outputPath)
	for _, privateKey := range privateKeys {
		if privateKey == "" {
			continue
		}
		privateKeyPath, err := filepath.Abs(privateKey)
		if err != nil {
			return fmt.Errorf("cannot resolve private key path %q: %w", privateKey, err)
		}
		if outputPath == privateKeyPath {
			return fmt.Errorf("output %q must not replace private key %q", output, privateKey)
		}
		if outputInfoErr == nil {
			if privateKeyInfo, err := goos.Stat(privateKeyPath); err == nil && goos.SameFile(outputInfo, privateKeyInfo) {
				return fmt.Errorf("output %q must not replace private key %q", output, privateKey)
			}
		}
	}
	return nil
}
