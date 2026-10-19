package common

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/configuration"
)

// EnsureStandardOutputSafe rejects regular output files that alias configured
// evidence, state, configuration or a supplied private identity. Pipes and
// invocation-owned buffers remain supported.
func EnsureStandardOutputSafe(ctx context.Context, stdout io.Writer, configPath string, conf *configuration.Configuration, identityFiles []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	output, ok := stdout.(*os.File)
	if !ok {
		return nil
	}
	outputInfo, err := output.Stat()
	if err != nil {
		return fmt.Errorf("cannot inspect standard output: %w", err)
	}
	if !outputInfo.Mode().IsRegular() {
		return nil
	}
	if conf == nil {
		return fmt.Errorf("nil configuration")
	}
	var location *outputLocation
	locationChecked := false
	guard := &fileOutputGuard{info: outputInfo, label: "standard output"}
	checkFile := func(path, description string) error {
		return guard.check(ctx, path, description)
	}
	checkDirectory := func(path, description string) error {
		if path == "" {
			return nil
		}
		if !locationChecked {
			resolved, err := inspectOutputLocation(ctx, output, outputInfo)
			if err != nil {
				return err
			}
			location, locationChecked = resolved, true
		}
		if location != nil {
			outside, err := location.excludesDirectory(ctx, path, description)
			if err != nil || outside {
				return err
			}
		}
		return EnsureFileDoesNotAliasDirectoryFile(ctx, "standard output", outputInfo, path, description)
	}
	if err := checkFile(configPath, "configuration file"); err != nil {
		return err
	}
	for _, path := range identityFiles {
		if err := checkFile(path, "decryption identity"); err != nil {
			return err
		}
	}
	if err := checkConfiguredSSHFiles(ctx, conf, checkFile); err != nil {
		return err
	}
	if sessionFs, ok := conf.Session.V.(*configuration.SessionFs); ok {
		if err := checkDirectory(sessionFs.Storage, "session storage file"); err != nil {
			return err
		}
	}
	for index := range conf.Auditlogs {
		configured := &conf.Auditlogs[index]
		if !configured.Enabled && !configured.Recording.Enabled {
			continue
		}
		if configured.Enabled {
			if err := checkDirectory(configured.Directory, "journal file"); err != nil {
				return err
			}
		}
		if err := checkFile(configured.IdentityFile, "audit signing identity"); err != nil {
			return err
		}
		if err := checkFile(string(configured.EncryptionPublicKeyFile), "encryption public key"); err != nil {
			return err
		}
		if configured.Recording.Enabled {
			if err := checkDirectory(configured.Recording.Directory, "recording file"); err != nil {
				return err
			}
		}
		checkSftp := func(targets configuration.AuditlogTargets) error {
			for index := range targets {
				sftp, ok := targets[index].V.(*configuration.AuditlogTargetSftp)
				if !ok {
					continue
				}
				if err := checkFile(string(sftp.KnownHostsFile), "SFTP known-hosts file"); err != nil {
					return err
				}
				for _, path := range sftp.IdentityFiles {
					if err := checkFile(path, "SFTP identity"); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if err := checkSftp(configured.Targets); err != nil {
			return err
		}
		if configured.Recording.Enabled {
			if err := checkSftp(configured.Recording.Targets.Configured()); err != nil {
				return err
			}
		}
	}
	return nil
}

func EnsureFileDoesNotAliasDirectoryFile(ctx context.Context, output string, outputInfo fs.FileInfo, directory, description string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	initial, err := os.Stat(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("cannot inspect protected directory %q: %w", directory, err)
	}
	if !initial.IsDir() {
		if os.SameFile(outputInfo, initial) {
			return fmt.Errorf("output %q must not replace %s %q", output, description, directory)
		}
		return nil
	}
	var visit func(string) error
	visit = func(current string) (resultErr error) {
		if err := ctx.Err(); err != nil {
			return err
		}
		directory, err := os.Open(current)
		if err != nil {
			return fmt.Errorf("cannot inspect protected path %q: %w", current, err)
		}
		defer func() { resultErr = errors.Join(resultErr, directory.Close()) }()
		for {
			entries, readErr := directory.ReadDir(256)
			for _, entry := range entries {
				if err := ctx.Err(); err != nil {
					return err
				}
				path := filepath.Join(current, entry.Name())
				if entry.IsDir() {
					if err := visit(path); err != nil {
						return err
					}
					continue
				}
				info, err := os.Stat(path)
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				if err != nil {
					return fmt.Errorf("cannot inspect protected path %q: %w", path, err)
				}
				if os.SameFile(outputInfo, info) {
					return fmt.Errorf("output %q must not replace %s %q", output, description, path)
				}
			}
			if readErr == io.EOF {
				return nil
			}
			if readErr != nil {
				return fmt.Errorf("cannot inspect protected path %q: %w", current, readErr)
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}
	return visit(directory)
}
