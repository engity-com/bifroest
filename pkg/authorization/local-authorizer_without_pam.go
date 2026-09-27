//go:build unix && (!cgo || without_pam || (!linux && !darwin))

package authorization

import (
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func (this *LocalAuthorizer) checkPassword(req PasswordRequest, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	if err := this.assertNoPamServiceConfigured(); err != nil {
		return "", nil, false, err
	}
	return this.checkPasswordViaRepository(req, requestedUsername, validatePassword)
}

func (this *LocalAuthorizer) checkInteractive(req InteractiveRequest, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	if err := this.assertNoPamServiceConfigured(); err != nil {
		return "", nil, false, err
	}
	return this.checkInteractiveViaRepository(req, requestedUsername, validatePassword)
}

func (this *LocalAuthorizer) assertNoPamServiceConfigured() error {
	if v := this.conf.PamService; v != "" {
		return errors.Config.Newf("this build of Engity's Bifröst does not support PAM, so configuration parameter pamService must be empty; got: %q", v)
	}
	return nil
}

func checkLocalAccount(pamService, _, _ string) (bool, error) {
	if pamService != "" {
		return false, errors.Config.Newf("this build of Engity's Bifröst does not support PAM, so configuration parameter pamService must be empty; got: %q", pamService)
	}
	return true, nil
}
