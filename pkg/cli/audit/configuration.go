package audit

import (
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func FindConfigured(conf *configuration.Configuration, name configuration.AuditlogName) (*configuration.Auditlog, error) {
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

func resolveAuditSourceConfiguration[O common.ConfigurationOptions](ctx context.Context, options O, directory, recipient string, name configuration.AuditlogName) (configuration.AuditlogName, *configuration.Configuration, error) {
	if directory != "" {
		if options.GetConfiguration() != nil {
			return "", nil, fmt.Errorf("--source cannot be combined with --configuration")
		}
		if name.IsZero() {
			name = configuration.DefaultAuditlogName
		}
		if err := name.Validate(); err != nil {
			return "", nil, err
		}
		return name, &configuration.Configuration{Auditlogs: configuration.Auditlogs{{
			Name: name, Enabled: true, Directory: directory, EncryptionPublicKeyFile: bfcrypto.PublicKeysFile(recipient),
		}}}, nil
	}
	if recipient != "" {
		return "", nil, fmt.Errorf("--encryptionPublicKeyFile requires --source")
	}
	if name.IsZero() {
		name = configuration.DefaultAuditlogName
	}
	if err := name.Validate(); err != nil {
		return "", nil, err
	}
	conf, err := common.ResolveConfiguration(ctx, options)
	return name, conf, err
}
