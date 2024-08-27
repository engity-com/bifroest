//go:build (!cgo || without_pam) && linux

package authorization

import (
	"fmt"

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
		return fmt.Errorf("this version of Engity's Bifröst is build without PAM support therefore configuration parameter pamService needs to be leave empty; but was: %q", v)
	}
	return nil
}
