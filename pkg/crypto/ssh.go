package crypto

import (
	"fmt"
	"github.com/engity-com/bifroest/pkg/sys"
	"golang.org/x/crypto/ssh"
	"os"
)

func DoWithEachAuthorizedKey[R any](requireExistence bool, callback func(ssh.PublicKey) (result R, canContinue bool, err error), files ...string) (result R, err error) {
	fail := func(err error) (R, error) {
		var empty R
		return empty, err
	}
	failf := func(message string, args ...any) (R, error) {
		return fail(fmt.Errorf(message, args...))
	}

	for _, file := range files {
		rest, err := os.ReadFile(file)
		if !requireExistence && sys.IsNotExist(err) {
			continue
		}
		if err != nil {
			return failf("failed to read authorized keys file %q: %v", file, err)
		}
		var entry int
		for len(rest) > 0 {
			var pub ssh.PublicKey
			pub, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
			if err != nil {
				return failf("failed to parse entry #%d of authorized keys file %q: %v", entry, file, err)
			}
			var canContinue bool
			result, canContinue, err = callback(pub)
			if err != nil {
				return failf("failed to evaluate entry #%d of authorized keys file %q: %v", entry, file, err)
			}
			if !canContinue {
				return result, nil
			}
			entry++
		}
	}
	return result, nil
}
