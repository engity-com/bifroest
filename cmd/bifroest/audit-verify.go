package main

import (
	"context"
	"fmt"
	"io"
	goos "os"
	"strings"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type auditVerifyOpts struct {
	configuration           configuration.Ref
	configurationPath       string
	sourceDirectory         string
	encryptionPublicKeyFile string
	auditlog                configuration.AuditlogName
	decryptionIdentityFiles []string
	expectedProducerIds     []string
	requireFull             bool
}

func registerAuditVerifyCmd(parent *kingpin.CmdClause) {
	opts := auditVerifyOpts{}
	cmd := parent.Command("verify", "Verify an audit journal without modifying it.").
		Action(func(*kingpin.ParseContext) error { return doAuditVerifyOutput(&opts, goos.Stdout) })
	cmd.Flag("configuration", "Configuration file (defaults to "+defaultConfigurationRef+" without --source).").
		Short('c').PlaceHolder("<path>").StringVar(&opts.configurationPath)
	cmd.Flag("source", "Complete auditlog directory for offline verification without a configuration.").
		PlaceHolder("<path>").StringVar(&opts.sourceDirectory)
	cmd.Flag("encryptionPublicKeyFile", "Expected encryption recipient for keyless offline verification.").
		PlaceHolder("<path>").StringVar(&opts.encryptionPublicKeyFile)
	registerAuditDecryptionIdentityFlags(cmd, &opts.decryptionIdentityFiles)
	registerAuditTrustAnchorFlags(cmd, &opts.expectedProducerIds)
	cmd.Flag("require-full", "Require decryption and full verification of encrypted audit records.").BoolVar(&opts.requireFull)
	cmd.Arg("auditlogName", "Configured auditlog, or optional label for an offline journal (default: default).").SetValue(&opts.auditlog)
}

func doAuditVerify(opts *auditVerifyOpts) error {
	return doAuditVerifyOutput(opts, io.Discard)
}

func doAuditVerifyOutput(opts *auditVerifyOpts, stdout io.Writer) error {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	if stdout == nil {
		return fmt.Errorf("nil stdout")
	}
	name, conf, err := resolveAuditSourceConfiguration(&opts.configuration, opts.configurationPath, opts.sourceDirectory, opts.encryptionPublicKeyFile, opts.auditlog)
	if err != nil {
		return err
	}
	configured, err := findConfiguredAuditlog(conf, name)
	if err != nil {
		return err
	}
	expectedProducerIds, err := parseAuditTrustAnchors(opts.expectedProducerIds, []*configuration.Auditlog{configured})
	if err != nil {
		return err
	}
	var source audit.JournalSource
	if opts.sourceDirectory != "" {
		source, err = offlineAuditJournalSource(configured, expectedProducerIds[configured.Name], opts.decryptionIdentityFiles, opts.encryptionPublicKeyFile)
	} else {
		source, err = configuredAuditJournalSource(configured, opts.decryptionIdentityFiles, expectedProducerIds[configured.Name])
	}
	if err != nil {
		return err
	}
	validate := func() error {
		return ensureAuditDestinationSafe("-", stdout, opts.configuration.GetFilename(), conf, opts.decryptionIdentityFiles)
	}
	if err := validate(); err != nil {
		return err
	}
	if opts.requireFull && source.ExpectedEncryptionRecipient != "" && len(source.DecryptionIdentities) == 0 {
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
	_, err = fmt.Fprintf(stdout, "verified (scope: %s)\n", scope)
	return err
}

func resolveAuditSourceConfiguration(ref *configuration.Ref, path, directory, recipient string, name configuration.AuditlogName) (configuration.AuditlogName, *configuration.Configuration, error) {
	if directory != "" {
		if path != "" || !ref.IsZero() {
			return "", nil, fmt.Errorf("--source cannot be combined with --configuration")
		}
		if name.IsZero() {
			name = "default"
		}
		if err := name.Validate(); err != nil {
			return "", nil, err
		}
		return name, &configuration.Configuration{Auditlogs: []configuration.Auditlog{{
			Name: name, Enabled: true, Directory: directory,
			EncryptionPublicKeyFile: bfcrypto.PublicKeysFile(recipient),
		}}}, nil
	}
	if recipient != "" {
		return "", nil, fmt.Errorf("--encryptionPublicKeyFile requires --source")
	}
	if name.IsZero() {
		return "", nil, fmt.Errorf("auditlogName is required without --source")
	}
	if err := name.Validate(); err != nil {
		return "", nil, err
	}
	if path != "" || len(ref.Get().Auditlogs) == 0 {
		if path == "" {
			path = defaultConfigurationRef
		}
		if err := ref.Set(path); err != nil {
			return "", nil, err
		}
	}
	return name, ref.Get(), nil
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
	cmd.Flag("expectedProducerId", "Trusted 64-hex producer ID for one auditlog, or <auditlogName>=<producer-id> for multiple.").
		PlaceHolder("<producer-id|auditlogName=producer-id>").
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
