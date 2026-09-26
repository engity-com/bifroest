package main

import (
	"bytes"
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"io/fs"
	goos "os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/sys"
)

type auditExportOpts struct {
	configuration           configuration.Ref
	configurationPath       string
	sourceDirectory         string
	encryptionPublicKeyFile string
	auditlog                configuration.AuditlogName
	output                  string
	force                   bool
	decryptionIdentityFiles []string
	expectedProducerIds     []string
	withSensitive           bool
}

const maxAuditOutputSize = 128 << 20

type boundedAuditOutput struct {
	bytes.Buffer
	limit int
}

func (this *boundedAuditOutput) Write(content []byte) (int, error) {
	limit := this.limit
	if limit == 0 {
		limit = maxAuditOutputSize
	}
	if len(content) > limit-this.Len() {
		return 0, fmt.Errorf("audit output exceeds %d bytes", limit)
	}
	return this.Buffer.Write(content)
}

func registerAuditExportCmd(parent *kingpin.CmdClause) {
	opts := auditExportOpts{output: "-"}
	cmd := parent.Command("export", "Export a verified audit journal as JSON Lines.").
		Action(func(*kingpin.ParseContext) error { return doAuditExport(&opts, goos.Stdout) })
	registerAuditExportFlags(cmd, &opts)
	cmd.Arg("auditlogName", "Configured auditlog, or optional label for an offline journal (default: default).").SetValue(&opts.auditlog)
}

func registerAuditExportFlags(cmd *kingpin.CmdClause, opts *auditExportOpts) {
	cmd.Flag("configuration", "Configuration file (defaults to "+defaultConfigurationRef+" without --source).").
		Short('c').PlaceHolder("<path>").StringVar(&opts.configurationPath)
	cmd.Flag("source", "Complete auditlog directory for offline export without a configuration.").
		PlaceHolder("<path>").StringVar(&opts.sourceDirectory)
	cmd.Flag("encryptionPublicKeyFile", "Expected encryption recipient for keyless offline export.").
		PlaceHolder("<path>").StringVar(&opts.encryptionPublicKeyFile)
	registerAuditOutputFlags(cmd, &opts.output, &opts.force)
	registerAuditDecryptionIdentityFlags(cmd, &opts.decryptionIdentityFiles)
	registerAuditTrustAnchorFlags(cmd, &opts.expectedProducerIds)
	registerAuditSensitiveFlag(cmd, &opts.withSensitive)
}

func doAuditExport(opts *auditExportOpts, stdout io.Writer) error {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	name, conf, err := resolveAuditSourceConfiguration(&opts.configuration, opts.configurationPath, opts.sourceDirectory, opts.encryptionPublicKeyFile, opts.auditlog)
	if err != nil {
		return err
	}
	configured, err := findConfiguredAuditlog(conf, name)
	if err != nil {
		return err
	}
	if !configured.Enabled {
		return fmt.Errorf("auditlog %q is disabled", configured.Name)
	}
	output, err := canonicalAuditOutput(opts.output)
	if err != nil {
		return err
	}
	validate := func() error {
		return ensureAuditDestinationSafe(output, stdout, opts.configuration.GetFilename(), conf, opts.decryptionIdentityFiles)
	}
	if err := validate(); err != nil {
		return err
	}
	expectedProducerIds, err := parseAuditTrustAnchors(opts.expectedProducerIds, []*configuration.Auditlog{configured})
	if err != nil {
		return err
	}
	var source audit.JournalSource
	if opts.sourceDirectory != "" {
		identities := opts.decryptionIdentityFiles
		if !opts.withSensitive {
			identities = nil
		}
		source, err = offlineAuditJournalSource(configured, expectedProducerIds[configured.Name], identities, opts.encryptionPublicKeyFile)
		if err != nil {
			return err
		}
	} else {
		identities := opts.decryptionIdentityFiles
		if !opts.withSensitive {
			identities = nil
		}
		source, err = configuredAuditJournalSource(configured, identities, expectedProducerIds[configured.Name])
		if err != nil {
			return err
		}
	}
	source.WithSensitive = opts.withSensitive
	verification, err := audit.VerifyLiveJournals(context.Background(), []audit.JournalSource{source})
	if err != nil {
		return err
	}
	return writeAuditOutput(output, opts.force, stdout, verification, audit.RecordOrderChain, validate)
}

func offlineAuditJournalSource(configured *configuration.Auditlog, producerId audit.ProducerId, identityFiles []string, recipientFile string) (audit.JournalSource, error) {
	if producerId.IsZero() {
		return audit.JournalSource{}, fmt.Errorf("--source requires --expectedProducerId from an independent trust source")
	}
	source := audit.JournalSource{Name: configured.Name.String(), Directory: configured.Directory, ExpectedProducerId: producerId}
	if recipientFile != "" {
		publicKey, err := audit.ResolveEncryptionPublicKey("", configured.EncryptionPublicKeyFile)
		if err != nil {
			return audit.JournalSource{}, err
		}
		source.ExpectedEncryptionRecipient, err = audit.EncryptionRecipientFingerprint(publicKey)
		if err != nil {
			return audit.JournalSource{}, err
		}
	}
	for _, path := range identityFiles {
		key, err := loadAuditPrivateKey(path)
		if err != nil {
			return audit.JournalSource{}, fmt.Errorf("cannot load audit decryption identity %q: %w", path, err)
		}
		source.DecryptionIdentities = append(source.DecryptionIdentities, key)
	}
	if source.ExpectedEncryptionRecipient == "" && len(source.DecryptionIdentities) == 1 {
		recipient, err := bfcrypto.NewAgeSshRecipient(source.DecryptionIdentities[0].PublicKey().ToSsh())
		if err != nil {
			return audit.JournalSource{}, err
		}
		source.ExpectedEncryptionRecipient = recipient.Fingerprint()
	} else if source.ExpectedEncryptionRecipient == "" && len(source.DecryptionIdentities) > 1 {
		return audit.JournalSource{}, fmt.Errorf("multiple decryption identities require --encryptionPublicKeyFile")
	}
	return source, nil
}

func registerAuditSensitiveFlag(cmd *kingpin.CmdClause, target *bool) {
	cmd.Flag("with-sensitive", "Include private event fields; encrypted journals require a matching decryption identity.").BoolVar(target)
}

func registerAuditOutputFlags(cmd *kingpin.CmdClause, output *string, force *bool) {
	cmd.Flag("output", "Output file (its parent must exist) or - for stdout.").Default("-").PlaceHolder("<path|->").StringVar(output)
	cmd.Flag("force", "Replace an existing output file.").BoolVar(force)
}

func writeAuditOutput(path string, force bool, stdout io.Writer, verification *audit.Verification, order audit.RecordOrder, validate func() error) error {
	var content boundedAuditOutput
	if err := verification.ExportJSONLines(&content, order); err != nil {
		return err
	}
	if path == "-" {
		if validate != nil {
			if err := validate(); err != nil {
				return err
			}
		}
		written, err := stdout.Write(content.Bytes())
		if err == nil && written != content.Len() {
			return io.ErrShortWrite
		}
		return err
	}
	if err := writeAuditOutputFile(path, content.Bytes(), force, validate); err != nil {
		return fmt.Errorf("cannot install audit output at %q: %w", path, err)
	}
	return nil
}

func ensureAuditDestinationSafe(output string, stdout io.Writer, configPath string, conf *configuration.Configuration, identityFiles []string) error {
	if output == "-" {
		return ensureAuditStandardOutputSafe(stdout, configPath, conf, identityFiles)
	}
	if err := ensureAuditOutputSafe(output, conf); err != nil {
		return err
	}
	if configPath != "" {
		if err := ensureAuditOutputDoesNotReplaceFile(output, configPath, "configuration file"); err != nil {
			return err
		}
	}
	return ensureBootstrapOutputIsNotPrivateKey(output, identityFiles...)
}

func ensureAuditStandardOutputSafe(stdout io.Writer, configPath string, conf *configuration.Configuration, identityFiles []string) error {
	output, ok := stdout.(*goos.File)
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
	checkFile := func(path, description string) error {
		if path == "" {
			return nil
		}
		info, err := goos.Stat(path)
		if goerrors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("cannot inspect %s %q: %w", description, path, err)
		}
		if goos.SameFile(outputInfo, info) {
			return fmt.Errorf("standard output must not replace %s %q", description, path)
		}
		return nil
	}
	checkDirectory := func(path, description string) error {
		if path == "" {
			return nil
		}
		return ensureAuditFileDoesNotAliasDirectoryFile("standard output", outputInfo, path, description)
	}
	if err := checkFile(configPath, "configuration file"); err != nil {
		return err
	}
	for _, path := range identityFiles {
		if err := checkFile(path, "decryption identity"); err != nil {
			return err
		}
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

func ensureAuditOutputSafe(output string, conf *configuration.Configuration) error {
	if output == "-" {
		return nil
	}
	if output == "" {
		return fmt.Errorf("output path is empty")
	}
	if conf == nil {
		return fmt.Errorf("nil configuration")
	}
	absoluteOutput, err := sys.CanonicalPath(output)
	if err != nil {
		return fmt.Errorf("cannot resolve output path %q: %w", output, err)
	}
	if sessionFs, ok := conf.Session.V.(*configuration.SessionFs); ok {
		absoluteStorage, err := ensureAuditOutputOutsideDirectory(output, absoluteOutput, sessionFs.Storage, "session storage")
		if err != nil {
			return err
		}
		if err := ensureAuditOutputDoesNotAliasDirectoryFile(output, absoluteStorage, "session storage file"); err != nil {
			return err
		}
	}
	for index := range conf.Auditlogs {
		configured := &conf.Auditlogs[index]
		if !configured.Enabled && !configured.Recording.Enabled {
			continue
		}
		if configured.Enabled {
			absoluteJournal, err := ensureAuditOutputOutsideDirectory(output, absoluteOutput, configured.Directory, fmt.Sprintf("auditlog %q journal", configured.Name))
			if err != nil {
				return err
			}
			if err := ensureAuditOutputDoesNotAliasDirectoryFile(output, absoluteJournal, "journal file"); err != nil {
				return err
			}
		}
		if err := ensureBootstrapOutputIsNotPrivateKey(output, configured.IdentityFile); err != nil {
			return err
		}
		if !configured.EncryptionPublicKeyFile.IsZero() {
			if err := ensureAuditOutputDoesNotReplaceFile(output, string(configured.EncryptionPublicKeyFile), "encryption public key"); err != nil {
				return err
			}
		}
		if configured.Recording.Enabled {
			if _, err := ensureAuditOutputOutsideDirectory(output, absoluteOutput, configured.Recording.Directory, fmt.Sprintf("auditlog %q recording directory", configured.Name)); err != nil {
				return err
			}
		}
		for targetIndex := range configured.Targets {
			target := &configured.Targets[targetIndex]
			sftp, ok := target.V.(*configuration.AuditlogTargetSftp)
			if !ok {
				continue
			}
			if !sftp.KnownHostsFile.IsZero() {
				if err := ensureAuditOutputDoesNotReplaceFile(output, string(sftp.KnownHostsFile), "SFTP known-hosts file"); err != nil {
					return err
				}
			}
			if err := ensureBootstrapOutputIsNotPrivateKey(output, sftp.IdentityFiles...); err != nil {
				return err
			}
		}
		if !configured.Recording.Enabled {
			continue
		}
		for _, target := range configured.Recording.Targets.Configured() {
			sftp, ok := target.V.(*configuration.AuditlogTargetSftp)
			if !ok {
				continue
			}
			if !sftp.KnownHostsFile.IsZero() {
				if err := ensureAuditOutputDoesNotReplaceFile(output, string(sftp.KnownHostsFile), "Recording SFTP known-hosts file"); err != nil {
					return err
				}
			}
			if err := ensureBootstrapOutputIsNotPrivateKey(output, sftp.IdentityFiles...); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureAuditOutputOutsideDirectory(output, absoluteOutput, directory, description string) (string, error) {
	absoluteDirectory, err := sys.CanonicalPath(directory)
	if err != nil {
		return "", fmt.Errorf("cannot resolve %s path %q: %w", description, directory, err)
	}
	relative, err := filepath.Rel(absoluteDirectory, absoluteOutput)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("output %q must not be inside %s %q", output, description, directory)
	}
	inside, err := auditOutputTraversesDirectory(output, directory)
	if err != nil {
		return "", err
	}
	if inside {
		return "", fmt.Errorf("output %q must not be inside %s %q", output, description, directory)
	}
	return absoluteDirectory, nil
}

func ensureAuditOutputDoesNotAliasDirectoryFile(output, directory, description string) error {
	outputInfo, err := goos.Stat(output)
	if goerrors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot inspect output path %q: %w", output, err)
	}
	return ensureAuditFileDoesNotAliasDirectoryFile(output, outputInfo, directory, description)
}

func ensureAuditFileDoesNotAliasDirectoryFile(output string, outputInfo fs.FileInfo, directory, description string) error {
	if _, err := goos.Stat(directory); goerrors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("cannot inspect protected directory %q: %w", directory, err)
	}
	return filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("cannot inspect protected path %q: %w", path, walkErr)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := goos.Stat(path)
		if goerrors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("cannot inspect protected path %q: %w", path, err)
		}
		if goos.SameFile(outputInfo, info) {
			return fmt.Errorf("output %q must not replace %s %q", output, description, path)
		}
		return nil
	})
}

func ensureAuditOutputDoesNotReplaceFile(output, protected, description string) error {
	outputPath, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("cannot resolve output path %q: %w", output, err)
	}
	protectedPath, err := filepath.Abs(protected)
	if err != nil {
		return fmt.Errorf("cannot resolve %s path %q: %w", description, protected, err)
	}
	if outputPath == protectedPath {
		return fmt.Errorf("output %q must not replace %s %q", output, description, protected)
	}
	outputInfo, outputErr := goos.Stat(outputPath)
	protectedInfo, protectedErr := goos.Stat(protectedPath)
	if outputErr == nil && protectedErr == nil && goos.SameFile(outputInfo, protectedInfo) {
		return fmt.Errorf("output %q must not replace %s %q", output, description, protected)
	}
	return nil
}

func auditOutputTraversesDirectory(output, directory string) (bool, error) {
	directoryInfo, err := goos.Stat(directory)
	if goerrors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot inspect journal path %q: %w", directory, err)
	}
	current, err := filepath.Abs(output)
	if err != nil {
		return false, fmt.Errorf("cannot resolve output path %q: %w", output, err)
	}
	for {
		info, statErr := goos.Stat(current)
		if statErr == nil && info.IsDir() && goos.SameFile(info, directoryInfo) {
			return true, nil
		}
		if statErr != nil && !goerrors.Is(statErr, fs.ErrNotExist) {
			return false, fmt.Errorf("cannot inspect output path %q: %w", current, statErr)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false, nil
		}
		current = parent
	}
}

func canonicalAuditOutput(output string) (string, error) {
	if output == "-" {
		return output, nil
	}
	resolved, err := sys.CanonicalPath(output)
	if err != nil {
		return "", fmt.Errorf("cannot resolve output path %q: %w", output, err)
	}
	parent := filepath.Dir(resolved)
	info, err := goos.Stat(parent)
	if err != nil {
		return "", fmt.Errorf("output parent directory %q must already exist: %w", parent, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("output parent %q is not a directory", parent)
	}
	return resolved, nil
}
