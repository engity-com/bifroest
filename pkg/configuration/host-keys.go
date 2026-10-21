package configuration

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

// EnsureHostPrivateKeysWithPaths resolves the configured host key files and
// checks each key against the configured restrictions.
func EnsureHostPrivateKeysWithPaths(conf *Configuration) ([]crypto.PrivateKey, []string, error) {
	if conf == nil {
		return nil, nil, fmt.Errorf("nil configuration")
	}
	keys := &conf.Ssh.Keys
	paths, err := keys.HostKeys.Render(struct{}{})
	if err != nil {
		return nil, nil, errors.Config.Newf("cannot render hostKeys: %w", err)
	}

	var result []crypto.PrivateKey
	var resultPaths []string
	for _, path := range paths {
		if path == "" {
			continue
		}
		key, err := crypto.EnsureKeyFile(path, &crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot ensure host key: %w", err)
		}
		allowed, err := keys.KeyAllowed(key)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot check if host key %q is allowed or not: %w", path, err)
		}
		if !allowed {
			return nil, nil, fmt.Errorf("host key %q is not allowed by restrictions", path)
		}
		result = append(result, key)
		resultPaths = append(resultPaths, path)
	}
	return result, resultPaths, nil
}
