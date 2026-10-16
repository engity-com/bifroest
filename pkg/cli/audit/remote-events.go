package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	goos "os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/management"
)

func doRemoteAuditEvents(ctx context.Context, target management.Target, opts AuditEventsOptions, output io.Writer) (resultErr error) {
	if target.Host == "" {
		return fmt.Errorf("remote audit events require a target and options")
	}
	if !opts.WithSensitive {
		return fmt.Errorf("--expectedProducerId for auditlog events requires --with-sensitive")
	}
	if opts.ConfigurationPath != "" {
		return fmt.Errorf("--configuration is a local file path and cannot be used with a remote target")
	}
	expected, err := expectedAuditEventsProducerID(target, opts.ExpectedProducerID)
	if err != nil {
		return err
	}
	identities := opts.IdentityFiles
	if len(identities) == 0 {
		path, err := management.AuditPrivateKey(target)
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
	header, err := management.DownloadAuditSnapshot(ctx, target, opts.Auditlog.String(), root)
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
		key, err := LoadAuditPrivateKey(path)
		if err != nil {
			return err
		}
		source.DecryptionIdentities = append(source.DecryptionIdentities, key)
	}
	verified, err := audit.VerifyJournals(ctx, []audit.JournalSource{source})
	if err != nil {
		return err
	}
	filter := EventFilter{
		Name: opts.EventName, Flow: opts.FlowName, Since: opts.Since, Until: opts.Until, Limit: opts.Limit,
	}
	records, err := FilterEvents(verified.Records(), filter, true)
	if err != nil {
		return err
	}
	return format.WriteAuditEvents(output, opts.Format, records, true)
}

func expectedAuditEventsProducerID(remote management.Target, configured string) (audit.ProducerId, error) {
	if configured == "" {
		var err error
		configured, err = management.ExpectedRecordingProducerID(remote)
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
