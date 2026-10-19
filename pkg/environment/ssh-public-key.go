package environment

import (
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
)

// SshPublicKey exposes only configured public identities. Certificate keys are
// taken from the running repository; ordinary identities must have static paths
// and must already exist. Exporting never generates a missing private key.
func (this *RepositoryFacade) SshPublicKey(flow configuration.FlowName, authority bool, identityIndex uint) (ssh.PublicKey, error) {
	entry, exists := this.entries[flow]
	if !exists {
		return nil, fmt.Errorf("flow %q does not exist", flow)
	}
	repository, ok := entry.(*SshRepository)
	if !ok {
		return nil, fmt.Errorf("flow %q does not use an SSH environment", flow)
	}
	if authority {
		if repository.certificateKeys == nil {
			return nil, fmt.Errorf("flow %q does not configure an SSH certificate authority", flow)
		}
		return repository.certificateKeys.authority.PublicKey(), nil
	}
	if repository.certificateKeys != nil {
		if identityIndex != 0 {
			return nil, fmt.Errorf("flow %q has only one certificate identity (index 0)", flow)
		}
		return repository.certificateKeys.subject.PublicKey(), nil
	}
	if identityIndex >= uint(len(repository.conf.IdentityFiles)) {
		return nil, fmt.Errorf("flow %q has no configured SSH identity at index %d", flow, identityIndex)
	}
	path := repository.conf.IdentityFiles[identityIndex]
	if path.IsZero() || !path.IsHardCoded() {
		return nil, fmt.Errorf("flow %q SSH identity at index %d must have a static non-empty path", flow, identityIndex)
	}
	key, err := crypto.EnsureKeyFile(path.String(), nil, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot read existing SSH identity for flow %q: %w", flow, err)
	}
	return key.PublicKey().ToSsh(), nil
}
