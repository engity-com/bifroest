package main

import (
	"context"
	"fmt"

	"github.com/alecthomas/kingpin/v2"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type auditVerifyOpts struct {
	configuration           configuration.Ref
	auditlog                configuration.AuditlogName
	decryptionIdentityFiles []string
}

func registerAuditVerifyCmd(parent *kingpin.CmdClause) {
	opts := auditVerifyOpts{}
	cmd := parent.Command("verify", "Verify an audit journal without modifying it.").
		Action(func(*kingpin.ParseContext) error { return doAuditVerify(&opts) })
	registerConfigurationFlag(cmd, &opts.configuration)
	registerAuditDecryptionIdentityFlags(cmd, &opts.decryptionIdentityFiles)
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
	source, err := configuredAuditJournalSource(configured, opts.decryptionIdentityFiles)
	if err != nil {
		return err
	}
	return audit.VerifyJournalIntegrity(context.Background(), []audit.JournalSource{source})
}

func configuredAuditJournalSource(configured *configuration.Auditlog, decryptionIdentityFiles []string) (audit.JournalSource, error) {
	if configured == nil {
		return audit.JournalSource{}, fmt.Errorf("nil auditlog configuration")
	}
	if !configured.Enabled {
		return audit.JournalSource{}, fmt.Errorf("auditlog %q is disabled", configured.Name)
	}
	privateKey, err := loadAuditPrivateKey(configured.IdentityFile)
	if err != nil {
		return audit.JournalSource{}, fmt.Errorf("cannot load identity of auditlog %q: %w", configured.Name, err)
	}
	identity, err := audit.NewIdentity(privateKey)
	if err != nil {
		return audit.JournalSource{}, fmt.Errorf("cannot use identity of auditlog %q: %w", configured.Name, err)
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
	matchingDecryptionIdentity := false
	for _, path := range decryptionIdentityFiles {
		key, err := loadAuditPrivateKey(path)
		if err != nil {
			return audit.JournalSource{}, fmt.Errorf("cannot load audit decryption identity %q: %w", path, err)
		}
		decryptionIdentities = append(decryptionIdentities, key)
		if encryptionRecipient != "" && ssh.FingerprintSHA256(key.PublicKey().ToSsh()) == encryptionRecipient {
			matchingDecryptionIdentity = true
		}
	}
	if encryptionRecipient != "" && !matchingDecryptionIdentity {
		return audit.JournalSource{}, fmt.Errorf("auditlog %q requires a matching --decryptionIdentityFile", configured.Name)
	}
	return audit.JournalSource{
		Name:                        configured.Name.String(),
		Directory:                   configured.Journal.Directory,
		ExpectedProducerId:          identity.ProducerId(),
		ExpectedEncryptionRecipient: encryptionRecipient,
		DecryptionIdentities:        decryptionIdentities,
	}, nil
}

func registerAuditDecryptionIdentityFlags(cmd *kingpin.CmdClause, target *[]string) {
	cmd.Flag("decryptionIdentityFile", "Private SSH key for decrypting audit records; repeat for multiple keys.").
		PlaceHolder("<path>").
		StringsVar(target)
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
