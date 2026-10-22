package service

import (
	stdcrypto "crypto"
	"fmt"
	"os"

	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/https"
)

func (this *service) prepareHTTPS() error {
	if !this.Configuration.Http.IsEnabled() {
		return nil
	}
	// Archived encrypted evidence remains confidential even when that auditlog
	// is now disabled. Audit best-effort policy must not waive transport key safety.
	for _, auditlog := range this.Configuration.Auditlogs {
		if !auditlog.Enabled && !auditlog.Recording.Enabled && !auditlog.EncryptionPublicKeyFile.IsZero() {
			if _, err := os.Stat(string(auditlog.EncryptionPublicKeyFile)); os.IsNotExist(err) && auditlog.EncryptionPublicKey.IsZero() {
				continue
			}
		}
		recipients, err := audit.ResolveEncryptionPublicKey(auditlog.EncryptionPublicKey, auditlog.EncryptionPublicKeyFile)
		if err != nil {
			return fmt.Errorf("cannot verify configured audit recipient separation for HTTPS")
		}
		if err := recipients.ForEach(func(_ int, key gossh.PublicKey, _ string) (bool, error) {
			public, err := crypto.PublicKeyFromSsh(key)
			if err != nil {
				return false, err
			}
			this.httpsForbiddenKeys = append(this.httpsForbiddenKeys, public)
			return true, nil
		}); err != nil {
			return fmt.Errorf("cannot inspect audit recipient identities for HTTPS")
		}
	}
	endpoint, err := https.NewEndpoint(this.Configuration.Http, https.EndpointOptions{ValidateKey: this.validateHTTPSKey})
	if err != nil {
		return fmt.Errorf("cannot prepare HTTPS endpoint: %w", err)
	}
	this.https = endpoint
	return nil
}

func (this *service) validateHTTPSKey(key stdcrypto.PublicKey) error {
	public, err := crypto.PublicKeyFromSdk(key)
	if err != nil {
		return fmt.Errorf("cannot inspect HTTPS key identity")
	}
	for _, other := range this.httpsForbiddenKeys {
		if public.IsEqualTo(other) {
			return fmt.Errorf("HTTPS/ACME key must be distinct from SSH, audit signing, SFTP and audit encryption keys")
		}
	}
	return nil
}
