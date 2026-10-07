package verify

import (
	"context"
	"fmt"
	"io"
	"strings"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	audit2 "github.com/engity-com/bifroest/pkg/cli/audit"
	. "github.com/engity-com/bifroest/pkg/cli/audit/common"
	"github.com/engity-com/bifroest/pkg/cli/audit/export"
	. "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	. "github.com/engity-com/bifroest/pkg/cli/recording/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/management"
)

type opts struct {
	configuration.EmptyStrOpts
	configuration.AuditlogNameOpts
	DecryptionIdentityFilesOpts
	TrustAnchorsOpts
	management.RequireFullVerificationOpts
	SourceDirectory         string `flag:"source" placeholder:"<path>" description:"Complete auditlog directory for offline verification without a configuration."`
	EncryptionPublicKeyFile string `flag:"encryptionPublicKeyFile" placeholder:"<path>" description:"Expected encryption recipient for keyless offline verification."`

	commandRoot string // Is this really required??
}

type optsWithFormat struct {
	opts
	format.Opts
}

var remoteAuditVerifyOpts = map[string]*opts{}

func Register(_ context.Context, c cli.ContainerRequirementSetters, _ Usage) {
	o := opts{}
	o.commandRoot = c.FullCommand()
	remoteAuditVerifyOpts[c.FullCommand()] = &o

	if o.commandRoot == "audit" {
		c.AddCommand(cli.NewCommand[optsWithFormat]().
			WithName("verify").
			WithDescription("Verify a signed audit journal without modifying it.").
			WithHandler(handleWithFormat),
		)
	} else {
		c.AddCommand(cli.NewCommand[opts]().
			WithName("verify").
			WithDescription("Verify a signed audit journal without modifying it.").
			WithHandler(handle),
		)
	}

}

func handleToVoid(ctx context.Context, o opts) error {
	ctx = ContextWithStdInOut(ctx, nil, io.Discard)
	return handle(ctx, o)
}

func handle(ctx context.Context, o opts) error {
	return handleWithFormat(ctx, optsWithFormat{o, format.Opts{}})
}

func handleWithFormat(ctx context.Context, o optsWithFormat) error {
	name, conf, err := ResolveAuditlogSourceConfiguration(&o.Configuration, o.configurationPath, o.SourceDirectory, o.EncryptionPublicKeyFile, o.Auditlog)
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
		source, err = export.offlineAuditJournalSource(configured, expectedProducerIds[configured.Name], o.DecryptionIdentityFiles, o.EncryptionPublicKeyFile)
	} else {
		source, err = configuredAuditJournalSource(configured, o.DecryptionIdentityFiles, expectedProducerIds[configured.Name])
	}
	if err != nil {
		return err
	}
	validate := func() error {
		return export.ensureAuditDestinationSafe(ctx, "-", o.configuration.GetFilename(), conf, o.DecryptionIdentityFiles)
	}
	if err := validate(); err != nil {
		return err
	}
	if o.RequireFull && source.ExpectedEncryptionRecipient != "" && len(source.DecryptionIdentities) == 0 {
		return fmt.Errorf("full verification of encrypted audit journal requires --decryptionIdentityFile")
	}
	if err := audit.VerifyLiveJournalIntegrity(context.Background(), []audit.JournalSource{source}); err != nil {
		return err
	}
	scope := "full"
	if source.ExpectedEncryptionRecipient != "" && len(source.DecryptionIdentities) == 0 {
		scope = "outer"
	}
	if err := validate(); err != nil {
		return err
	}
	return management.WriteVerification(ctx, audit2.selectedAuditFormat(o.commandRoot, o.Format), scope)
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
