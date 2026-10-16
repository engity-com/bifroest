package audit

import (
	"context"
	"fmt"
	"strings"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type verifyOptions struct {
	common.ExecutableConfigurationOpts
	configuration.AuditlogNameOpts
	DecryptionIdentityFilesOpts
	TrustAnchorsOpts
	common.RequireFullVerificationOpts
	format.Opts
	SourceDirectory         string `flag:"source" placeholder:"<path>" description:"Complete auditlog directory for offline verification without a configuration."`
	EncryptionPublicKeyFile string `flag:"encryptionPublicKeyFile" placeholder:"<path>" description:"Expected encryption recipient for keyless offline verification."`
}

type managementVerifyOptions struct {
	common.RequireFullVerificationOpts
	format.Opts
	ConfiguredAuditlogOptions
}

func registerVerify(c cli.ContainerRequirementSetters) {
	c.AddCommand(
		cli.NewCommand[managementVerifyOptions]("verify", "Verify a signed audit journal without modifying it.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementVerify),
	)
	c.AddCommand(
		cli.NewCommand[verifyOptions]("verify", "Verify a signed audit journal without modifying it.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleVerify),
	)
}

func handleManagementVerify(ctx context.Context, opts managementVerifyOptions) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Audit == nil {
		return fmt.Errorf("management audit repository is unavailable")
	}
	scope, err := access.Audit.Verify(ctx, opts.Name, opts.RequireFull)
	if err != nil {
		return err
	}
	return format.WriteVerification(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, opts.Format), scope)
}

func handleVerify(ctx context.Context, o verifyOptions) error {
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		if o.Configuration != nil {
			return fmt.Errorf("--configuration cannot be combined with a remote target")
		}
		return runRemoteAudit(ctx, target, remoteAuditOptions{
			Operation: remoteVerify, Names: []configuration.AuditlogName{o.Auditlog},
			TrustAnchors: o.ExpectedProducerIds, IdentityFiles: o.DecryptionIdentityFiles,
			SourceDirectory: o.SourceDirectory,
			RecipientFile:   o.EncryptionPublicKeyFile, RequireFull: o.RequireFull,
			Format: o.Format,
		}, cli.StdoutOfContext(ctx))
	}
	name, conf, err := resolveAuditSourceConfiguration(ctx, o, o.SourceDirectory, o.EncryptionPublicKeyFile, o.Auditlog)
	if err != nil {
		return err
	}
	configured, err := FindConfigured(conf, name)
	if err != nil {
		return err
	}
	expectedProducerIds, err := ParseAuditTrustAnchors(o.ExpectedProducerIds, []*configuration.Auditlog{configured})
	if err != nil {
		return err
	}
	var source audit.JournalSource
	if o.SourceDirectory != "" {
		source, err = offlineAuditJournalSource(configured, expectedProducerIds[configured.Name], o.DecryptionIdentityFiles, o.EncryptionPublicKeyFile)
	} else {
		source, err = configuredAuditJournalSource(configured, o.DecryptionIdentityFiles, expectedProducerIds[configured.Name])
	}
	if err != nil {
		return err
	}
	validate := func() error {
		return EnsureAuditDestinationSafe("-", cli.StdoutOfContext(ctx), conf.Filename, conf, o.DecryptionIdentityFiles)
	}
	if err := validate(); err != nil {
		return err
	}
	if o.RequireFull && source.ExpectedEncryptionRecipient != "" && len(source.DecryptionIdentities) == 0 {
		return fmt.Errorf("full verification of encrypted audit journal requires --decryptionIdentityFile")
	}
	if err := audit.VerifyLiveJournalIntegrity(ctx, []audit.JournalSource{source}); err != nil {
		return err
	}
	scope := "full"
	if source.ExpectedEncryptionRecipient != "" && len(source.DecryptionIdentities) == 0 {
		scope = "outer"
	}
	if err := validate(); err != nil {
		return err
	}
	return format.WriteVerification(cli.StdoutOfContext(ctx), o.Format, scope)
}

func configuredAuditJournalSource(configured *configuration.Auditlog, decryptionIdentityFiles []string, expectedProducerId audit.ProducerId) (audit.JournalSource, error) {
	if configured == nil {
		return audit.JournalSource{}, fmt.Errorf("nil auditlog configuration")
	}
	if !configured.Enabled {
		return audit.JournalSource{}, fmt.Errorf("auditlog %q is disabled", configured.Name)
	}
	if expectedProducerId.IsZero() {
		privateKey, err := LoadAuditPrivateKey(configured.IdentityFile)
		if err != nil {
			return audit.JournalSource{}, fmt.Errorf("cannot load identity of auditlog %q: %w", configured.Name, err)
		}
		identity, err := audit.NewIdentity(privateKey)
		if err != nil {
			return audit.JournalSource{}, fmt.Errorf("cannot use identity of auditlog %q: %w", configured.Name, err)
		}
		expectedProducerId = identity.ProducerId()
	}
	encryptionPublicKey, err := audit.ResolveEncryptionPublicKey(configured.EncryptionPublicKey, configured.EncryptionPublicKeyFile)
	if err != nil {
		return audit.JournalSource{}, fmt.Errorf("cannot load encryption public key of auditlog %q: %w", configured.Name, err)
	}
	encryptionRecipient, err := audit.EncryptionRecipientFingerprint(encryptionPublicKey)
	if err != nil && !encryptionPublicKey.IsZero() {
		return audit.JournalSource{}, fmt.Errorf("cannot use encryption public key of auditlog %q: %w", configured.Name, err)
	}
	decryptionIdentities := make([]bfcrypto.PrivateKey, 0, len(decryptionIdentityFiles))
	for _, path := range decryptionIdentityFiles {
		key, err := LoadAuditPrivateKey(path)
		if err != nil {
			return audit.JournalSource{}, fmt.Errorf("cannot load audit decryption identity %q: %w", path, err)
		}
		decryptionIdentities = append(decryptionIdentities, key)
	}
	return audit.JournalSource{
		Name:                        configured.Name.String(),
		Directory:                   configured.Directory,
		ExpectedProducerId:          expectedProducerId,
		ExpectedEncryptionRecipient: encryptionRecipient,
		DecryptionIdentities:        decryptionIdentities,
	}, nil
}

func ParseAuditTrustAnchors(raw []string, selected []*configuration.Auditlog) (map[configuration.AuditlogName]audit.ProducerId, error) {
	selectedNames := make(map[configuration.AuditlogName]struct{}, len(selected))
	for _, configured := range selected {
		if configured != nil {
			selectedNames[configured.Name] = struct{}{}
		}
	}
	result := make(map[configuration.AuditlogName]audit.ProducerId, len(raw))
	for _, value := range raw {
		rawName, rawProducerId, found := strings.Cut(value, "=")
		if !found && len(selectedNames) == 1 {
			for selectedName := range selectedNames {
				rawName, rawProducerId, found = string(selectedName), value, true
			}
		}
		name := configuration.AuditlogName(rawName)
		if !found || rawName == "" || rawProducerId == "" {
			return nil, fmt.Errorf("illegal --expectedProducerId %q: expected <producer-id> for one source or <auditlogName>=<producer-id>", value)
		}
		if err := name.Validate(); err != nil {
			return nil, fmt.Errorf("illegal --expectedProducerId %q: %w", value, err)
		}
		if _, ok := selectedNames[name]; !ok {
			return nil, fmt.Errorf("--expectedProducerId references unselected auditlog %q", name)
		}
		if _, duplicate := result[name]; duplicate {
			return nil, fmt.Errorf("--expectedProducerId for auditlog %q is duplicated", name)
		}
		var producerId audit.ProducerId
		if err := producerId.Set(rawProducerId); err != nil {
			return nil, fmt.Errorf("illegal --expectedProducerId for auditlog %q: %w", name, err)
		}
		if producerId.IsZero() {
			return nil, fmt.Errorf("--expectedProducerId for auditlog %q must not be zero", name)
		}
		result[name] = producerId
	}
	return result, nil
}
