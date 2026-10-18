package audit

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

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/sys"
)

type exportOptions struct {
	common.ExecutableConfigurationOpts
	configuration.AuditlogNameOpts
	SourceDirectory         string `flag:"source" profile:"executable" placeholder:"<path>" description:"Complete auditlog directory for offline verification without a configuration."`
	EncryptionPublicKeyFile string `flag:"encryptionPublicKeyFile" profile:"executable" placeholder:"<path>" description:"Expected encryption recipient for keyless offline export."`
	OutputOpts
	DecryptionIdentityFilesOpts
	TrustAnchorsOpts
	common.WithSensitiveOpts
}

type managementExportOptions struct {
	common.WithSensitiveOpts
	ConfiguredAuditlogOptions
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

func createAuditExportCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[managementExportOptions]("export", "Export verified audit events as JSON Lines.").
			WithAliases("decrypt").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementExport),
		cli.NewCommand[exportOptions]("export", "Export verified audit events as JSON Lines.").
			WithAliases("decrypt").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleAuditExport),
		cli.NewCommand[exportOptions]("export", "Export verified audit events as JSON Lines.").
			WithAliases("decrypt").
			WithProfiles(common.ProfileRemote).
			WithHandler(remoteHandleAuditExport),
	}
}

func handleManagementExport(ctx context.Context, opts managementExportOptions) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Audit == nil {
		return fmt.Errorf("management audit repository is unavailable")
	}
	return access.Audit.Export(ctx, []configuration.AuditlogName{opts.Name}, opts.WithSensitive,
		audit.RecordOrderChain, cli.StdoutOfContext(ctx))
}

func remoteHandleAuditExport(ctx context.Context, o exportOptions) error {
	if o.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	return runRemoteAudit(ctx, target, remoteAuditOptions{
		Operation: remoteExport, Names: []configuration.AuditlogName{o.Auditlog},
		TrustAnchors: o.ExpectedProducerIds, IdentityFiles: o.DecryptionIdentityFiles,
		SourceDirectory: o.SourceDirectory,
		RecipientFile:   o.EncryptionPublicKeyFile, Output: o.Output,
		Force: o.Force, WithSensitive: o.WithSensitive, Format: format.Text,
	}, cli.StdoutOfContext(ctx))
}

func handleAuditExport(ctx context.Context, o exportOptions) error {
	name, conf, err := resolveAuditSourceConfiguration(ctx, o, o.SourceDirectory, o.EncryptionPublicKeyFile, o.Auditlog)
	if err != nil {
		return err
	}
	configured, err := FindConfigured(conf, name)
	if err != nil {
		return err
	}
	if !configured.Enabled {
		return fmt.Errorf("auditlog %q is disabled", configured.Name)
	}
	output, err := CanonicalAuditOutput(o.Output)
	if err != nil {
		return err
	}
	stdout := cli.StdoutOfContext(ctx)
	validate := func() error {
		return EnsureAuditDestinationSafe(ctx, output, stdout, conf.Filename, conf, o.DecryptionIdentityFiles)
	}
	if err := validate(); err != nil {
		return err
	}
	expectedProducerIds, err := ParseAuditTrustAnchors(o.ExpectedProducerIds, []*configuration.Auditlog{configured})
	if err != nil {
		return err
	}
	var source audit.JournalSource
	if o.SourceDirectory != "" {
		identities := o.DecryptionIdentityFiles
		if !o.WithSensitive {
			identities = nil
		}
		source, err = offlineAuditJournalSource(configured, expectedProducerIds[configured.Name], identities, o.EncryptionPublicKeyFile)
		if err != nil {
			return err
		}
	} else {
		identities := o.DecryptionIdentityFiles
		if !o.WithSensitive {
			identities = nil
		}
		source, err = configuredAuditJournalSource(configured, identities, expectedProducerIds[configured.Name])
		if err != nil {
			return err
		}
	}
	source.WithSensitive = o.WithSensitive
	verification, err := audit.VerifyLiveJournals(ctx, []audit.JournalSource{source})
	if err != nil {
		return err
	}
	return writeAuditOutput(output, o.Force, stdout, verification, audit.RecordOrderChain, validate)
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
		key, err := LoadAuditPrivateKey(path)
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
	if err := WriteAuditOutputFile(path, content.Bytes(), force, validate); err != nil {
		return fmt.Errorf("cannot install audit output at %q: %w", path, err)
	}
	return nil
}

func EnsureAuditDestinationSafe(ctx context.Context, output string, stdout io.Writer, configPath string, conf *configuration.Configuration, identityFiles []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if output == "-" {
		return common.EnsureStandardOutputSafe(ctx, stdout, configPath, conf, identityFiles)
	}
	if err := ensureAuditOutputSafe(ctx, output, conf); err != nil {
		return err
	}
	if configPath != "" {
		if err := EnsureAuditOutputDoesNotReplaceFile(output, configPath, "configuration file"); err != nil {
			return err
		}
	}
	return common.EnsureBootstrapOutputIsNotPrivateKey(output, identityFiles...)
}

func ensureAuditOutputSafe(ctx context.Context, output string, conf *configuration.Configuration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
		if err := ensureAuditOutputDoesNotAliasDirectoryFile(ctx, output, absoluteStorage, "session storage file"); err != nil {
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
			if err := ensureAuditOutputDoesNotAliasDirectoryFile(ctx, output, absoluteJournal, "journal file"); err != nil {
				return err
			}
		}
		if err := common.EnsureBootstrapOutputIsNotPrivateKey(output, configured.IdentityFile); err != nil {
			return err
		}
		if !configured.EncryptionPublicKeyFile.IsZero() {
			if err := EnsureAuditOutputDoesNotReplaceFile(output, string(configured.EncryptionPublicKeyFile), "encryption public key"); err != nil {
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
				if err := EnsureAuditOutputDoesNotReplaceFile(output, string(sftp.KnownHostsFile), "SFTP known-hosts file"); err != nil {
					return err
				}
			}
			if err := common.EnsureBootstrapOutputIsNotPrivateKey(output, sftp.IdentityFiles...); err != nil {
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
				if err := EnsureAuditOutputDoesNotReplaceFile(output, string(sftp.KnownHostsFile), "Recording SFTP known-hosts file"); err != nil {
					return err
				}
			}
			if err := common.EnsureBootstrapOutputIsNotPrivateKey(output, sftp.IdentityFiles...); err != nil {
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

func ensureAuditOutputDoesNotAliasDirectoryFile(ctx context.Context, output, directory, description string) error {
	outputInfo, err := goos.Stat(output)
	if goerrors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot inspect output path %q: %w", output, err)
	}
	return common.EnsureFileDoesNotAliasDirectoryFile(ctx, output, outputInfo, directory, description)
}

func EnsureAuditOutputDoesNotReplaceFile(output, protected, description string) error {
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

func CanonicalAuditOutput(output string) (string, error) {
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
