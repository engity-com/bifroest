package service

import (
	"context"
	"fmt"
	"io"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
)

type managementAuditOperations struct {
	service               *service
	allowArtifactTransfer bool
}

func (this managementAuditOperations) Verify(ctx context.Context, name configuration.AuditlogName, requireFull bool) (string, error) {
	sources, err := this.service.managementAuditSources([]configuration.AuditlogName{name}, false)
	if err != nil {
		return "", err
	}
	scope := "full"
	if sources[0].ExpectedEncryptionRecipient != "" {
		if requireFull {
			return "", fmt.Errorf("full verification of encrypted auditlog %q requires a local private key; use bifroest @host audit verify", name)
		}
		scope = "outer"
	}
	if err := audit.VerifyLiveJournalIntegrity(ctx, sources); err != nil {
		return "", err
	}
	return scope, nil
}

func (this managementAuditOperations) Export(ctx context.Context, names []configuration.AuditlogName, sensitive bool, order audit.RecordOrder, output io.Writer) error {
	if sensitive && !this.allowArtifactTransfer {
		return fmt.Errorf("sensitive audit export requires allowArtifactTransfer in the management environment")
	}
	sources, err := this.service.managementAuditSources(names, sensitive)
	if err != nil {
		return err
	}
	verification, err := audit.VerifyLiveJournals(ctx, sources)
	if err != nil {
		return err
	}
	return verification.ExportJSONLines(output, order)
}

func (this *service) managementAuditSources(names []configuration.AuditlogName, sensitive bool) ([]audit.JournalSource, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("at least one auditlog is required")
	}
	sources := make([]audit.JournalSource, 0, len(names))
	for _, name := range names {
		if err := name.Validate(); err != nil {
			return nil, err
		}
		identity := this.auditIdentities[name]
		if identity == nil {
			return nil, fmt.Errorf("auditlog %q is not active", name)
		}
		found := false
		for _, conf := range this.Configuration.Auditlogs {
			if conf.Name != name {
				continue
			}
			if !conf.Enabled {
				return nil, fmt.Errorf("auditlog %q is disabled", name)
			}
			publicKey, err := audit.ResolveEncryptionPublicKey(conf.EncryptionPublicKey, conf.EncryptionPublicKeyFile)
			if err != nil {
				return nil, err
			}
			recipient, err := audit.EncryptionRecipientFingerprint(publicKey)
			if err != nil {
				return nil, err
			}
			sources = append(sources, audit.JournalSource{
				Name: name.String(), Directory: conf.Directory, ExpectedProducerId: identity.ProducerId(),
				ExpectedEncryptionRecipient: recipient, WithSensitive: sensitive,
			})
			found = true
			break
		}
		if !found {
			return nil, fmt.Errorf("auditlog %q does not exist", name)
		}
	}
	return sources, nil
}
