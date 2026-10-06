package service

import (
	"context"
	"fmt"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management"
)

func (this *service) managementAuditSources(names []string, sensitive bool) ([]audit.JournalSource, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("at least one auditlog is required")
	}
	sources := make([]audit.JournalSource, 0, len(names))
	for _, raw := range names {
		name := configuration.AuditlogName(raw)
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

func (this *service) registerManagementAuditCommands(parent *kingpin.CmdClause, task environment.Task, inheritedFormat *string, allowArtifactTransfer bool) {
	format := func(own string) management.Format {
		if inheritedFormat != nil && *inheritedFormat != "" {
			return management.Format(*inheritedFormat)
		}
		if own != "" {
			return management.Format(own)
		}
		return management.FormatTable
	}
	var producerName string
	producer := management.AuditArtifactCommand(parent, "producer-id")
	var producerFormat string
	if inheritedFormat == nil {
		management.VerificationFormatFlag(producer, &producerFormat)
	}
	producer.Arg("auditlogName", "Configured auditlog name.").Required().StringVar(&producerName)
	producer.Action(func(*kingpin.ParseContext) error {
		name := configuration.AuditlogName(producerName)
		if err := name.Validate(); err != nil {
			return err
		}
		identity := this.auditIdentities[name]
		if identity == nil {
			return fmt.Errorf("auditlog %q has no signing identity", name)
		}
		return management.WriteProducerID(task.SshSession(), format(producerFormat), identity.ProducerId().String())
	})
	var verifyName string
	var requireFull bool
	var verifyFormat string
	verify := management.AuditArtifactCommand(parent, "verify")
	management.RequireFullVerificationFlag(verify, &requireFull)
	if inheritedFormat == nil {
		management.VerificationFormatFlag(verify, &verifyFormat)
	}
	verify.Arg("auditlogName", "Configured auditlog name.").Required().StringVar(&verifyName)
	verify.Action(func(*kingpin.ParseContext) error {
		sources, err := this.managementAuditSources([]string{verifyName}, false)
		if err != nil {
			return err
		}
		scope := "full"
		if sources[0].ExpectedEncryptionRecipient != "" {
			if requireFull {
				return fmt.Errorf("full verification of encrypted auditlog %q requires a local private key; use bifroest @host audit verify", verifyName)
			}
			scope = "outer"
		}
		if err := audit.VerifyLiveJournalIntegrity(task.Context(), sources); err != nil {
			return err
		}
		return management.WriteVerification(task.SshSession(), format(verifyFormat), scope)
	})
	for _, verb := range []string{"export", "decrypt"} {
		var name string
		var sensitive bool
		command := management.AuditArtifactCommand(parent, verb)
		management.AuditSensitiveFlag(command, &sensitive)
		command.Arg("auditlogName", "Configured auditlog name.").Required().StringVar(&name)
		command.Action(func(*kingpin.ParseContext) error {
			if sensitive && !allowArtifactTransfer {
				return fmt.Errorf("sensitive audit export requires allowArtifactTransfer in the management environment")
			}
			if format("") != management.FormatTable {
				return fmt.Errorf("audit export has a fixed JSON Lines output; use auditlog events for structured views")
			}
			return this.exportManagementAudit(task.Context(), task, []string{name}, sensitive, audit.RecordOrderChain)
		})
	}
	var mergeNames []string
	var mergeSensitive bool
	merge := management.AuditArtifactCommand(parent, "merge")
	management.AuditSensitiveFlag(merge, &mergeSensitive)
	merge.Arg("auditlogName", "Configured auditlog names.").Required().StringsVar(&mergeNames)
	merge.Action(func(*kingpin.ParseContext) error {
		if mergeSensitive && !allowArtifactTransfer {
			return fmt.Errorf("sensitive audit export requires allowArtifactTransfer in the management environment")
		}
		if format("") != management.FormatTable {
			return fmt.Errorf("audit merge has a fixed JSON Lines output; use auditlog events for structured views")
		}
		return this.exportManagementAudit(task.Context(), task, mergeNames, mergeSensitive, audit.RecordOrderChronological)
	})
}

func (this *service) exportManagementAudit(ctx context.Context, task environment.Task, names []string, sensitive bool, order audit.RecordOrder) error {
	sources, err := this.managementAuditSources(names, sensitive)
	if err != nil {
		return err
	}
	verification, err := audit.VerifyLiveJournals(ctx, sources)
	if err != nil {
		return err
	}
	return verification.ExportJSONLines(task.SshSession(), order)
}
