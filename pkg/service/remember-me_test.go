package service

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestWebRememberMePolicyDiscoveryAndEnrollment(t *testing.T) {
	for _, mode := range []configuration.RememberMe{configuration.RememberMeForbidden, configuration.RememberMeAllowed, configuration.RememberMeAllowedAndEnabledByDefault, configuration.RememberMeEnforced} {
		t.Run(mode.String(), func(t *testing.T) {
			svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) { conf.Flows[0].Authorization.RememberMe = mode })
			for _, option := range webTestLoginOptions(t, handler, "Work") {
				require.Equal(t, mode, option.RememberMe)
			}
			login := webTestPassword(handler, "alice", "correct", "Work")
			token := webTestToken(t, login)
			var response struct {
				RememberMe string `json:"rememberMe"`
			}
			require.NoError(t, json.Unmarshal(login.Body.Bytes(), &response))
			require.Equal(t, mode.String(), response.RememberMe)
			key, public := rememberTestKey(t)
			if !mode.Allowed() {
				body, err := json.Marshal(map[string]string{"slug": "Work", "publicKey": public})
				require.NoError(t, err)
				require.Equal(t, http.StatusForbidden, webTestRequest(handler, "POST", "app.example.org", webAPI+"remember/enroll", string(body), token).Code)
				return
			}
			binding := rememberTestEnroll(t, handler, token, public, key)
			svc.Configuration.Flows[0].Authorization.RememberMe = configuration.RememberMeForbidden
			challenge := rememberTestStart(t, handler, "resume", "", binding.selector())
			require.Equal(t, http.StatusUnauthorized, rememberTestProve(t, handler, challenge, key).Code)
		})
	}
}

func TestSSHRememberMePolicyAndClientPreference(t *testing.T) {
	for _, mode := range []configuration.RememberMe{configuration.RememberMeForbidden, configuration.RememberMeAllowed, configuration.RememberMeAllowedAndEnabledByDefault, configuration.RememberMeEnforced} {
		for _, preference := range []string{"", "true", "off", "invalid"} {
			t.Run(mode.String()+"/"+preference, func(t *testing.T) {
				server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
					conf.Flows[0].Authorization.RememberMe = mode
					entry := &conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0]
					entry.AuthorizedKeys = ""
					require.NoError(t, entry.Password.Set("plain:correct"))
				})
				client, err := dialSdkMigrationServerWithClientConfig(server, func(conf *ssh.ClientConfig) {
					conf.Auth = []ssh.AuthMethod{ssh.PublicKeys(server.signer), ssh.Password("correct")}
				})
				require.NoError(t, err)
				t.Cleanup(func() { _ = client.Close() })
				channel, err := client.NewSession()
				require.NoError(t, err)
				if preference != "" {
					require.NoError(t, channel.Setenv("REMEMBER_ME", preference))
				}
				_, err = channel.Output("test")
				require.NoError(t, err)
				_ = channel.Close()
				channel, err = client.NewSession()
				require.NoError(t, err)
				_, err = channel.Output("another channel without a new preference")
				require.NoError(t, err)
				_ = channel.Close()
				expected := mode.Enabled(preference, preference != "")
				count := 0
				require.NoError(t, server.service.sessions.FindAll(t.Context(), func(ctx context.Context, sess session.Session) (bool, error) {
					count++
					registered, err := sess.HasPublicKey(ctx, server.signer.PublicKey())
					require.NoError(t, err)
					require.Equal(t, expected, registered)
					return true, nil
				}, nil))
				require.Equal(t, 1, count)
				returning, err := server.dial()
				if expected {
					require.NoError(t, err)
					plain, err := returning.NewSession()
					require.NoError(t, err)
					_, err = plain.Output("keep an existing registration without repeating opt-in")
					require.NoError(t, err)
					_ = plain.Close()
					optOut, err := returning.NewSession()
					require.NoError(t, err)
					require.NoError(t, optOut.Setenv("REMEMBER_ME", "no"))
					_, err = optOut.Output("stop remembering")
					require.NoError(t, err)
					_ = optOut.Close()
					require.NoError(t, returning.Close())
					again, err := server.dial()
					if mode == configuration.RememberMeEnforced {
						require.NoError(t, err)
						require.NoError(t, again.Close())
					} else {
						require.Error(t, err)
						if again != nil {
							_ = again.Close()
						}
					}
				} else {
					require.Error(t, err)
					if returning != nil {
						_ = returning.Close()
					}
				}
			})
		}
	}
}
