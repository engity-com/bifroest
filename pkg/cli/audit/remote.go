package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/management"
)

type remoteAuditOperation uint8

const (
	remoteVerify remoteAuditOperation = iota
	remoteExport
	remoteMerge
)

type remoteAuditOptions struct {
	Operation         remoteAuditOperation
	Names             []configuration.AuditlogName
	TrustAnchors      []string
	IdentityFiles     []string
	ConfigurationPath string
	SourceDirectory   string
	RecipientFile     string
	Output            string
	Force             bool
	WithSensitive     bool
	RequireFull       bool
	Format            format.Format
}

// runRemoteAudit receives invocation-owned options. The SSH server never sees
// local decryption keys, output paths or independently trusted producer IDs.
func runRemoteAudit(ctx context.Context, target management.Target, opts remoteAuditOptions, output io.Writer) (resultErr error) {
	if opts.ConfigurationPath != "" || opts.SourceDirectory != "" || opts.RecipientFile != "" {
		return fmt.Errorf("--source, --configuration and --encryptionPublicKeyFile are local/offline inputs and cannot be used with a remote target")
	}
	if opts.Operation != remoteVerify && opts.Format != format.Text {
		return fmt.Errorf("audit export and merge have a fixed JSON Lines output; use audit events for structured views")
	}
	if len(opts.Names) == 0 {
		return fmt.Errorf("at least one auditlog name is required")
	}
	anchors := opts.TrustAnchors
	if len(anchors) == 0 && len(opts.Names) == 1 {
		value, err := management.ExpectedRecordingProducerID(target)
		if err != nil {
			return err
		}
		if value != "" {
			anchors = []string{value}
		}
	}
	selected := make([]*configuration.Auditlog, 0, len(opts.Names))
	for _, name := range opts.Names {
		if err := name.Validate(); err != nil {
			return err
		}
		selected = append(selected, &configuration.Auditlog{Name: name})
	}
	producers, err := ParseAuditTrustAnchors(anchors, selected)
	if err != nil {
		return err
	}
	for _, name := range opts.Names {
		if producers[name].IsZero() {
			return fmt.Errorf("remote auditlog %q requires --expectedProducerId or X-ExpectedProducerId from an independent trust source", name)
		}
	}
	identityFiles := opts.IdentityFiles
	if len(identityFiles) == 0 && (opts.WithSensitive || opts.RequireFull || opts.Operation == remoteVerify) {
		path, err := management.AuditPrivateKey(target)
		if err != nil {
			return err
		}
		if path != "" {
			identityFiles = []string{path}
		}
	}
	if opts.Operation == remoteVerify || opts.Output == "" || opts.Output == "-" {
		if err := common.EnsureStandardOutputSafe(ctx, output, "", &configuration.Configuration{}, identityFiles); err != nil {
			return err
		}
	}
	if err := target.EnsureOutputSafe(ctx, opts.Output, output); err != nil {
		return err
	}
	var identities []bfcrypto.PrivateKey
	if opts.WithSensitive || opts.RequireFull || opts.Operation == remoteVerify {
		for _, path := range identityFiles {
			key, err := LoadAuditPrivateKey(path)
			if err != nil {
				return err
			}
			identities = append(identities, key)
		}
	}
	root, err := os.MkdirTemp("", "bifroest-remote-audit-*")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(root)) }()
	var sources []audit.JournalSource
	var destination configuration.Configuration
	for index, name := range opts.Names {
		localRoot := filepath.Join(root, fmt.Sprintf("%d", index))
		if err := os.Mkdir(localRoot, 0700); err != nil {
			return err
		}
		header, err := management.DownloadAuditSnapshot(ctx, target, name.String(), localRoot)
		if err != nil {
			return err
		}
		if header.Producer != producers[name].String() {
			return fmt.Errorf("remote auditlog %q has an unexpected producer ID", name)
		}
		journal := filepath.Join(localRoot, "journal")
		sources = append(sources, audit.JournalSource{
			Name: name.String(), Directory: journal, ExpectedProducerId: producers[name],
			ExpectedEncryptionRecipient: header.Recipient, DecryptionIdentities: identities,
			WithSensitive: opts.WithSensitive || opts.Operation == remoteVerify && len(identities) != 0,
		})
		destination.Auditlogs = append(destination.Auditlogs, configuration.Auditlog{Name: name, Enabled: true, Directory: journal})
	}
	if opts.Operation == remoteVerify {
		if opts.RequireFull && sources[0].ExpectedEncryptionRecipient != "" && len(identities) == 0 {
			return fmt.Errorf("full verification of encrypted audit journals requires a local --decryptionIdentityFile or X-AuditPrivateKey")
		}
		if err := audit.VerifyJournalIntegrity(ctx, sources); err != nil {
			return err
		}
		scope := "full"
		if sources[0].ExpectedEncryptionRecipient != "" && len(identities) == 0 {
			scope = "outer"
		}
		return format.WriteVerification(output, opts.Format, scope)
	}
	verified, err := audit.VerifyJournals(ctx, sources)
	if err != nil {
		return err
	}
	path := opts.Output
	if path == "" {
		path = "-"
	}
	path, err = CanonicalAuditOutput(path)
	if err != nil {
		return err
	}
	validate := func() error {
		// The destination may have become an SSH input alias during the download.
		if err := target.EnsureOutputSafe(ctx, path, output); err != nil {
			return err
		}
		return EnsureAuditDestinationSafe(ctx, path, output, "", &destination, identityFiles)
	}
	if err := validate(); err != nil {
		return err
	}
	order := audit.RecordOrderChain
	if opts.Operation == remoteMerge {
		order = audit.RecordOrderChronological
	}
	return writeAuditOutput(path, opts.Force, output, verified, order, validate)
}
