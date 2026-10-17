package audit

import (
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type AuditEventSource func(context.Context, string, configuration.AuditlogName, bool, []string) ([]audit.VerifiedRecord, error)

func ReadAuditEvents(ctx context.Context, conf *configuration.Configuration, name configuration.AuditlogName, expected audit.ProducerId, filter EventFilter, withSensitive bool, identities []string) ([]audit.VerifiedRecord, error) {
	if conf == nil || expected.IsZero() {
		return nil, fmt.Errorf("audit events require a configured journal and trusted producer ID")
	}
	selection, err := filter.selection(withSensitive)
	if err != nil {
		return nil, err
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
		verified, err := audit.SelectLiveJournalRecords(ctx, []audit.JournalSource{source}, selection)
		if err != nil {
			return nil, err
		}
		return verified.Records(), nil
	}
	return nil, fmt.Errorf("auditlog %q does not exist", name)
}
