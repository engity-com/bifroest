package common

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func ResolveAuditlogSourceConfiguration(conf *configuration.Configuration, path, directory, recipient string, name configuration.AuditlogName) (configuration.AuditlogName, *configuration.Configuration, error) {
	if directory != "" {
		if path != "" || !conf.IsZero() {
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
	if path != "" || len(conf.Get().Auditlogs) == 0 {
		if path == "" {
			path = configuration.DefaultRef
		}
		if err := conf.Set(path); err != nil {
			return "", nil, err
		}
	}
	return name, conf.Get(), nil
}
