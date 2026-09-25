package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type auditVerifyOpts struct {
	configuration           configuration.Ref
	auditlog                configuration.AuditlogName
	decryptionIdentityFiles []string
	expectedProducerIds     []string
}

func registerAuditVerifyCmd(parent *kingpin.CmdClause) {
	opts := auditVerifyOpts{}
	cmd := parent.Command("verify", "Verify an audit journal without modifying it.").
		Action(func(*kingpin.ParseContext) error { return doAuditVerify(&opts) })
	registerConfigurationFlag(cmd, &opts.configuration)
	registerAuditDecryptionIdentityFlags(cmd, &opts.decryptionIdentityFiles)
	registerAuditTrustAnchorFlags(cmd, &opts.expectedProducerIds)
	cmd.Arg("auditlogName", "Configured auditlog to verify.").Required().SetValue(&opts.auditlog)
}

func doAuditVerify(opts *auditVerifyOpts) error {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	configured, err := findConfiguredAuditlog(opts.configuration.Get(), opts.auditlog)
	if err != nil {
		return err
	}
	expectedProducerIds, err := parseAuditTrustAnchors(opts.expectedProducerIds, []*configuration.Auditlog{configured})
	if err != nil {
		return err
	}
	source, err := configuredAuditJournalSource(configured, opts.decryptionIdentityFiles, expectedProducerIds[configured.Name])
	if err != nil {
		return err
	}
	return audit.VerifyLiveJournalIntegrity(context.Background(), []audit.JournalSource{source})
}

func configuredAuditJournalSource(configured *configuration.Auditlog, decryptionIdentityFiles []string, expectedProducerId audit.ProducerId) (audit.JournalSource, error) {
	if configured == nil {
		return audit.JournalSource{}, fmt.Errorf("nil auditlog configuration")
	}
	if !configured.Enabled {
		return audit.JournalSource{}, fmt.Errorf("auditlog %q is disabled", configured.Name)
	}
	if expectedProducerId.IsZero() {
		privateKey, err := loadAuditPrivateKey(configured.IdentityFile)
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
		key, err := loadAuditPrivateKey(path)
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

func registerAuditDecryptionIdentityFlags(cmd *kingpin.CmdClause, target *[]string) {
	cmd.Flag("decryptionIdentityFile", "Private SSH key for decrypting audit records; repeat for multiple keys.").
		PlaceHolder("<path>").
		StringsVar(target)
}

func registerAuditTrustAnchorFlags(cmd *kingpin.CmdClause, target *[]string) {
	cmd.Flag("expectedProducerId", "Trusted producer ID as <auditlogName>=<64-hex>; repeat for multiple auditlogs.").
		PlaceHolder("<auditlogName>=<producer-id>").
		StringsVar(target)
}

func parseAuditTrustAnchors(raw []string, selected []*configuration.Auditlog) (map[configuration.AuditlogName]audit.ProducerId, error) {
	selectedNames := make(map[configuration.AuditlogName]struct{}, len(selected))
	for _, configured := range selected {
		if configured != nil {
			selectedNames[configured.Name] = struct{}{}
		}
	}
	result := make(map[configuration.AuditlogName]audit.ProducerId, len(raw))
	for _, value := range raw {
		rawName, rawProducerId, found := strings.Cut(value, "=")
		name := configuration.AuditlogName(rawName)
		if !found || rawName == "" || rawProducerId == "" {
			return nil, fmt.Errorf("illegal --expectedProducerId %q: expected <auditlogName>=<producer-id>", value)
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

func findConfiguredAuditlog(conf *configuration.Configuration, name configuration.AuditlogName) (*configuration.Auditlog, error) {
	if conf == nil {
		return nil, fmt.Errorf("nil configuration")
	}
	for index := range conf.Auditlogs {
		if conf.Auditlogs[index].Name == name {
			return &conf.Auditlogs[index], nil
		}
	}
	return nil, fmt.Errorf("auditlog %q does not exist", name)
}
