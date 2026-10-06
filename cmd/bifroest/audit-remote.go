package main

import (
	"context"
	"fmt"
	"io"
	goos "os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/managementclient"
)

func doRemoteAuditCommand(ctx context.Context, target *managementTarget, command string, output io.Writer) error {
	if target == nil {
		return fmt.Errorf("a remote target is required")
	}
	var names []configuration.AuditlogName
	var anchors, identityFiles []string
	var sourceDirectory, configPath, recipientFile string
	var outPath string
	var force, withSensitive, requireFull bool
	switch command {
	case "audit verify":
		opts := remoteAuditVerifyOpts
		if opts == nil {
			return fmt.Errorf("audit verify is not registered")
		}
		names, anchors, identityFiles, sourceDirectory, configPath, recipientFile, requireFull = []configuration.AuditlogName{opts.auditlog}, opts.expectedProducerIds, opts.decryptionIdentityFiles, opts.sourceDirectory, opts.configurationPath, opts.encryptionPublicKeyFile, opts.requireFull
	case "audit export", "audit decrypt":
		opts := remoteAuditExportOpts
		if command == "audit decrypt" {
			opts = remoteAuditDecryptOpts
		}
		if opts == nil {
			return fmt.Errorf("audit export is not registered")
		}
		names, anchors, identityFiles, sourceDirectory, configPath, recipientFile = []configuration.AuditlogName{opts.auditlog}, opts.expectedProducerIds, opts.decryptionIdentityFiles, opts.sourceDirectory, opts.configurationPath, opts.encryptionPublicKeyFile
		outPath, force, withSensitive = opts.output, opts.force, opts.withSensitive
	case "audit merge":
		opts := remoteAuditMergeOpts
		if opts == nil {
			return fmt.Errorf("audit merge is not registered")
		}
		for _, name := range opts.auditlogs {
			names = append(names, configuration.AuditlogName(name))
		}
		anchors, identityFiles, configPath = opts.expectedProducerIds, opts.decryptionIdentityFiles, opts.configurationPath
		outPath, force, withSensitive = opts.output, opts.force, opts.withSensitive
	case "audit producer-id":
		opts := remoteAuditProducerIdOpts
		if opts == nil {
			return fmt.Errorf("audit producer-id is not registered")
		}
		names, configPath = []configuration.AuditlogName{opts.auditlog}, opts.configurationPath
	default:
		return fmt.Errorf("unsupported remote audit command %q", command)
	}
	if sourceDirectory != "" || configPath != "" || recipientFile != "" {
		return fmt.Errorf("--source, --configuration and --encryptionPublicKeyFile are local/offline inputs and cannot be used with a remote target")
	}
	if len(names) == 0 {
		return fmt.Errorf("at least one auditlog name is required")
	}
	remote := managementclient.Target{Host: target.RawHost, User: target.User, Port: target.Port, ExplicitPort: target.ExplicitPort}
	if len(anchors) == 0 && len(names) == 1 && command != "audit producer-id" {
		value, err := managementclient.ExpectedRecordingProducerID(remote)
		if err != nil {
			return err
		}
		if value != "" {
			anchors = []string{value}
		}
	}
	selected := make([]*configuration.Auditlog, 0, len(names))
	for _, name := range names {
		if err := name.Validate(); err != nil {
			return err
		}
		selected = append(selected, &configuration.Auditlog{Name: name})
	}
	producerIDs, err := parseAuditTrustAnchors(anchors, selected)
	if err != nil {
		return err
	}
	if command != "audit producer-id" {
		for _, name := range names {
			if producerIDs[name].IsZero() {
				return fmt.Errorf("remote auditlog %q requires --expectedProducerId or X-ExpectedProducerId from an independent trust source", name)
			}
		}
	}
	if len(identityFiles) == 0 && (withSensitive || requireFull || command == "audit verify") {
		path, err := managementclient.AuditPrivateKey(remote)
		if err != nil {
			return err
		}
		if path != "" {
			identityFiles = []string{path}
		}
	}
	var identities []bfcrypto.PrivateKey
	if withSensitive || requireFull || command == "audit verify" {
		for _, path := range identityFiles {
			key, err := loadAuditPrivateKey(path)
			if err != nil {
				return err
			}
			identities = append(identities, key)
		}
	}
	root, err := goos.MkdirTemp("", "bifroest-remote-audit-*")
	if err != nil {
		return err
	}
	defer goos.RemoveAll(root)
	var sources []audit.JournalSource
	var destination configuration.Configuration
	for index, name := range names {
		localRoot := filepath.Join(root, fmt.Sprintf("%d", index))
		if err := goos.Mkdir(localRoot, 0700); err != nil {
			return err
		}
		header, err := managementclient.DownloadAuditSnapshot(ctx, remote, name.String(), localRoot)
		if err != nil {
			return err
		}
		if command == "audit producer-id" {
			_, err := fmt.Fprintln(output, header.Producer)
			return err
		}
		if header.Producer != producerIDs[name].String() {
			return fmt.Errorf("remote auditlog %q has an unexpected producer ID", name)
		}
		journal := filepath.Join(localRoot, "journal")
		sources = append(sources, audit.JournalSource{
			Name: name.String(), Directory: journal, ExpectedProducerId: producerIDs[name], ExpectedEncryptionRecipient: header.Recipient,
			DecryptionIdentities: identities, WithSensitive: withSensitive || command == "audit verify" && len(identities) != 0,
		})
		destination.Auditlogs = append(destination.Auditlogs, configuration.Auditlog{Name: name, Enabled: true, Directory: journal})
	}
	if command == "audit verify" {
		if requireFull && sources[0].ExpectedEncryptionRecipient != "" && len(identities) == 0 {
			return fmt.Errorf("full verification of encrypted audit journals requires a local --decryptionIdentityFile or X-AuditPrivateKey")
		}
		if err := audit.VerifyJournalIntegrity(ctx, sources); err != nil {
			return err
		}
		scope := "full"
		if sources[0].ExpectedEncryptionRecipient != "" && len(identities) == 0 {
			scope = "outer"
		}
		_, err := fmt.Fprintf(output, "verified (scope: %s)\n", scope)
		return err
	}
	verified, err := audit.VerifyJournals(ctx, sources)
	if err != nil {
		return err
	}
	if outPath == "" {
		outPath = "-"
	}
	outPath, err = canonicalAuditOutput(outPath)
	if err != nil {
		return err
	}
	validate := func() error {
		return ensureAuditDestinationSafe(outPath, output, "", &destination, identityFiles)
	}
	if err := validate(); err != nil {
		return err
	}
	order := audit.RecordOrderChain
	if command == "audit merge" {
		order = audit.RecordOrderChronological
	}
	return writeAuditOutput(outPath, force, output, verified, order, validate)
}
