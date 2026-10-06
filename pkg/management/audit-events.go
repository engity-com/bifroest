package management

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type AuditEventSource func(context.Context, string, configuration.AuditlogName, bool, []string) ([]audit.VerifiedRecord, error)

func ReadAuditEvents(ctx context.Context, conf *configuration.Configuration, name configuration.AuditlogName, expected audit.ProducerId, withSensitive bool, identities []string) ([]audit.VerifiedRecord, error) {
	if conf == nil || expected.IsZero() {
		return nil, fmt.Errorf("audit events require a configured journal and trusted producer ID")
	}
	for _, selected := range conf.Auditlogs {
		if selected.Name != name {
			continue
		}
		if !selected.Enabled {
			return nil, fmt.Errorf("auditlog %q is disabled", name)
		}
		publicKey, err := audit.ResolveEncryptionPublicKey(selected.EncryptionPublicKey, selected.EncryptionPublicKeyFile)
		if err != nil {
			return nil, err
		}
		fingerprint, err := audit.EncryptionRecipientFingerprint(publicKey)
		if err != nil {
			return nil, err
		}
		source := audit.JournalSource{
			Name: name.String(), Directory: selected.Directory,
			ExpectedProducerId: expected, ExpectedEncryptionRecipient: fingerprint, WithSensitive: withSensitive,
		}
		if withSensitive {
			for _, path := range identities {
				key, err := bfcrypto.LoadSecurePrivateKeyFile(path, 1<<20)
				if err != nil {
					return nil, fmt.Errorf("cannot read local decryption identity %q: %w", path, err)
				}
				source.DecryptionIdentities = append(source.DecryptionIdentities, key)
			}
		}
		verified, err := audit.VerifyLiveJournals(ctx, []audit.JournalSource{source})
		if err != nil {
			return nil, err
		}
		return verified.Records(), nil
	}
	return nil, fmt.Errorf("auditlog %q does not exist", name)
}

type AuditEventFilter struct {
	Name  string
	Flow  string
	Since time.Time
	Until time.Time
	Limit int
}

func WriteAuditEvents(output io.Writer, format Format, records []audit.VerifiedRecord, filter AuditEventFilter, withSensitive bool) error {
	if filter.Flow != "" && !withSensitive {
		return fmt.Errorf("filtering audit events by flow requires --with-sensitive")
	}
	if filter.Limit < 0 {
		return fmt.Errorf("audit event limit cannot be negative")
	}
	selected := make([]audit.VerifiedRecord, 0)
	for _, record := range records {
		if filter.Name != "" && record.Event.Name != filter.Name ||
			filter.Flow != "" && record.Event.Flow != filter.Flow ||
			!filter.Since.IsZero() && record.RecordedAt.Before(filter.Since) ||
			!filter.Until.IsZero() && record.RecordedAt.After(filter.Until) {
			continue
		}
		selected = append(selected, record)
	}
	if filter.Limit > 0 && len(selected) > filter.Limit {
		selected = selected[len(selected)-filter.Limit:]
	}
	rows := make([][]string, 0, len(selected))
	for _, record := range selected {
		rows = append(rows, []string{record.RecordedAt.Format(time.RFC3339), record.Event.Name, string(record.Event.Domain), string(record.Event.Outcome), record.Id.String()})
	}
	if format == FormatTable && withSensitive {
		for index := range rows {
			rows[index] = append(rows[index], strings.TrimSpace(selected[index].Event.Flow))
		}
		return WriteList(output, format, []string{"RECORDED", "NAME", "DOMAIN", "OUTCOME", "ID", "FLOW"}, rows, selected)
	}
	return WriteList(output, format, []string{"RECORDED", "NAME", "DOMAIN", "OUTCOME", "ID"}, rows, selected)
}
