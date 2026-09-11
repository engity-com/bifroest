package environment

import (
	"fmt"
	"strings"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
	gossh "golang.org/x/crypto/ssh"
)

var sshCertificateKeyRequirement = crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}

func EnsureSshCertificateAuthority(flow *configuration.Flow) (crypto.PrivateKey, string, error) {
	if flow == nil {
		return nil, "", fmt.Errorf("nil flow")
	}
	conf, ok := flow.Environment.V.(*configuration.EnvironmentSsh)
	if !ok {
		return nil, "", fmt.Errorf("flow %q does not use an SSH environment", flow.Name)
	}
	if conf.Certificate == nil {
		return nil, "", fmt.Errorf("flow %q does not configure an SSH certificate", flow.Name)
	}
	key, path, err := ensureSshCertificateKey(conf.Certificate.AuthorityIdentityFile, "certificate authority")
	if err != nil {
		return nil, "", fmt.Errorf("cannot ensure SSH certificate authority for flow %q: %w", flow.Name, err)
	}
	return key, path, nil
}

func ValidateSshCertificateAuthority(authority crypto.PrivateKey, hostKeys []crypto.PrivateKey) error {
	if authority == nil {
		return fmt.Errorf("nil SSH certificate authority")
	}
	authorityFingerprint := gossh.FingerprintSHA256(authority.ToSsh().PublicKey())
	for _, hostKey := range hostKeys {
		if hostKey != nil && gossh.FingerprintSHA256(hostKey.ToSsh().PublicKey()) == authorityFingerprint {
			return fmt.Errorf("SSH certificate authority must not reuse an SSH server host key")
		}
	}
	return nil
}

func ensureSshCertificateIdentity(conf *configuration.EnvironmentSshCertificate) (crypto.PrivateKey, string, error) {
	return ensureSshCertificateKey(conf.IdentityFile, "certificate identity")
}

func ensureSshCertificateAuthority(conf *configuration.EnvironmentSshCertificate) (crypto.PrivateKey, string, error) {
	return ensureSshCertificateKey(conf.AuthorityIdentityFile, "certificate authority")
}

func ensureSshCertificateKey(configured template.String, kind string) (crypto.PrivateKey, string, error) {
	path := strings.TrimSpace(configured.String())
	if path == "" || !configured.IsHardCoded() {
		return nil, "", fmt.Errorf("SSH %s identity file has to be a static non-empty path", kind)
	}
	key, err := crypto.EnsureKeyFile(path, &sshCertificateKeyRequirement, nil)
	if err != nil {
		return nil, "", fmt.Errorf("cannot ensure SSH %s identity file %q: %w", kind, path, err)
	}
	return key, path, nil
}
