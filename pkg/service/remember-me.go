package service

import (
	"encoding/base64"
	"strings"
	"sync"

	essh "github.com/engity-com/ssh-server-go"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

type sshRememberCredentialContextKey struct{}
type sshRememberPreferenceContextKey struct{}
type sshRememberPreference struct {
	sync.Mutex
	value   string
	present bool
}

func prepareSSHRemember(ctx essh.Context, auth authorization.Authorization, method string, key ssh.PublicKey) {
	ctx.SetValue(sshRememberPreferenceContextKey{}, &sshRememberPreference{})
	ctx.SetValue(sshRememberCredentialContextKey{}, nil)
	if auth.FindSessionsPublicKey() == nil {
		ctx.SetValue(sshRememberCredentialContextKey{}, sshRememberCredential(auth, method, key))
	}
}

func (s *service) rememberMePolicy(flow configuration.FlowName) configuration.RememberMe {
	for _, configured := range s.Configuration.Flows {
		if configured.Name == flow {
			return configured.Authorization.RememberMePolicy()
		}
	}
	return configuration.RememberMeForbidden
}

// Read only the SSH client's original channel variables, before environment or
// authorized_keys layers can supply values. This controls future admissions.
func (s *service) rememberSSHClient(ctx essh.Context, auth authorization.Authorization, variables []string) error {
	if auth == nil || auth.FindSession() == nil {
		return nil
	}
	key, _ := ctx.Value(handshakeKeyCtxKey).(ssh.PublicKey)
	if key == nil {
		key = auth.FindSessionsPublicKey()
	}
	if key == nil {
		return nil
	}
	preference, _ := ctx.Value(sshRememberPreferenceContextKey{}).(*sshRememberPreference)
	if preference == nil {
		preference = &sshRememberPreference{}
	}
	preference.Lock()
	defer preference.Unlock()
	for _, variable := range variables {
		name, value, ok := strings.Cut(variable, "=")
		if ok && name == "REMEMBER_ME" {
			preference.value, preference.present = value, true
		}
	}
	policy := s.rememberMePolicy(auth.Flow())
	if !policy.Enabled(preference.value, preference.present) {
		if preference.present || !policy.Allowed() {
			return auth.FindSession().DeletePublicKey(ctx, key)
		}
		return nil // Absence of a new opt-in does not revoke an existing binding.
	}
	credential, ok := ctx.Value(sshRememberCredentialContextKey{}).(authentication.SessionCredential)
	if !ok {
		return nil
	} // A resumed key is already registered; do not relabel it.
	identity, err := authorization.AuthenticationOf(auth)
	if err != nil {
		return err
	}
	store, supported := auth.FindSession().(session.SSHRememberMeSession)
	if !supported {
		return nil
	}
	if err := store.RememberSSHKey(ctx, key, session.SSHRememberedCredential{Identity: identity, Credential: credential}); err != nil {
		s.logger().WithError(err).Warn("cannot register SSH RememberMe; primary login remains valid")
	}
	return nil
}

func sshRememberCredential(auth authorization.Authorization, method string, key ssh.PublicKey) authentication.SessionCredential {
	credential := authentication.SessionCredential{Kind: authorization.KindOf(auth), Method: method}
	if method == "public-key" && key != nil {
		credential.PublicKey = base64.StdEncoding.EncodeToString(key.Marshal())
	}
	return credential
}
