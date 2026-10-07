package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	goos "os"
	"path/filepath"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/management"
	"github.com/engity-com/bifroest/pkg/managementclient"
)

func doRemoteAuditEvents(ctx context.Context, target *managementTarget, opts *management.AuditEventsOptions, output io.Writer) (resultErr error) {
	if target == nil || opts == nil {
		return fmt.Errorf("remote audit events require a target and options")
	}
	if !opts.WithSensitive {
		return fmt.Errorf("--expectedProducerId for auditlog events requires --with-sensitive")
	}
	if opts.ConfigurationPath != "" {
		return fmt.Errorf("--configuration is a local file path and cannot be used with a remote target")
	}
	remote := managementclient.Target{Host: target.RawHost, User: target.User, Port: target.Port, ExplicitPort: target.ExplicitPort}
	expected, err := expectedAuditEventsProducerID(remote, opts.ExpectedProducerID)
	if err != nil {
		return err
	}
	identities := opts.IdentityFiles
	if len(identities) == 0 {
		path, err := managementclient.AuditPrivateKey(remote)
		if err != nil {
			return err
		}
		if path != "" {
			identities = []string{path}
		}
	}
	root, err := goos.MkdirTemp("", "bifroest-remote-audit-events-*")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, goos.RemoveAll(root)) }()
	header, err := managementclient.DownloadAuditSnapshot(ctx, remote, opts.Auditlog.String(), root)
	if err != nil {
		return err
	}
	if header.Producer != expected.String() {
		return fmt.Errorf("remote auditlog %q has an unexpected producer ID", opts.Auditlog)
	}
	source := audit.JournalSource{
		Name: opts.Auditlog.String(), Directory: filepath.Join(root, "journal"), ExpectedProducerId: expected,
		ExpectedEncryptionRecipient: header.Recipient, WithSensitive: true,
	}
	for _, path := range identities {
		key, err := loadAuditPrivateKey(path)
		if err != nil {
			return err
		}
		source.DecryptionIdentities = append(source.DecryptionIdentities, key)
	}
	verified, err := audit.VerifyJournals(ctx, []audit.JournalSource{source})
	if err != nil {
		return err
	}
	filter := management.AuditEventFilter{Name: opts.EventName, Flow: opts.FlowName, Limit: opts.Limit}
	if opts.Since != "" {
		if filter.Since, err = time.Parse(time.RFC3339, opts.Since); err != nil {
			return fmt.Errorf("invalid --since: %w", err)
		}
	}
	if opts.Until != "" {
		if filter.Until, err = time.Parse(time.RFC3339, opts.Until); err != nil {
			return fmt.Errorf("invalid --until: %w", err)
		}
	}
	return management.WriteAuditEvents(output, management.Format(opts.Format), verified.Records(), filter, true)
}

func expectedAuditEventsProducerID(remote managementclient.Target, configured string) (audit.ProducerId, error) {
	if configured == "" {
		var err error
		configured, err = managementclient.ExpectedRecordingProducerID(remote)
		if err != nil {
			return audit.ProducerId{}, err
		}
	}
	var expected audit.ProducerId
	if configured == "" || expected.Set(configured) != nil || expected.IsZero() {
		return audit.ProducerId{}, fmt.Errorf("remote sensitive audit events require an independently trusted --expectedProducerId or X-ExpectedProducerId in the SSH config")
	}
	return expected, nil
}
