//go:build linux && cgo && !without_pam

package service

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

const pamIntegrationContainerMarker = "/run/bifroest-pam-integration"

type nativePamFixture struct {
	service, access, environment, authCalls string
}

func nativePamTestFixture(t *testing.T) nativePamFixture {
	t.Helper()
	if os.Getenv("BIFROEST_TEST_PAM_IN_CONTAINER") != "1" {
		t.Skip("run mise run test:e2e:pam in its disposable Linux container")
	}
	marker, err := os.ReadFile(pamIntegrationContainerMarker)
	require.NoError(t, err, "refusing native account changes outside the owned PAM container")
	require.Equal(t, "bifroest-owned-pam-integration\n", string(marker))
	require.Equal(t, 0, os.Geteuid(), "native fixture needs container-local root, never host privilege escalation")
	root := t.TempDir()
	fixture := nativePamFixture{service: "bifroest-" + filepath.Base(root), access: filepath.Join(root, "access"), environment: filepath.Join(root, "environment"), authCalls: filepath.Join(root, "auth-calls")}
	run := func(input, name string, args ...string) {
		t.Helper()
		command := exec.CommandContext(t.Context(), name, args...)
		command.Stdin = strings.NewReader(input)
		output, err := command.CombinedOutput()
		require.NoError(t, err, "%s: %s", name, output)
	}
	run("", "useradd", "--no-create-home", "--shell=/bin/sh", "alice")
	t.Cleanup(func() {
		output, err := exec.Command("userdel", "alice").CombinedOutput()
		require.NoError(t, err, "remove owned container account: %s", output)
	})
	run("alice:correct\n", "chpasswd")
	module := filepath.Join(root, "account_environment.so")
	run("", "gcc", "-shared", "-fPIC", "-Wall", "-Werror", "-o", module, "testdata/pam/account_environment.c", "-lpam")
	require.NoError(t, os.WriteFile(fixture.access, []byte("+ : ALL : ALL\n"), 0600))
	require.NoError(t, os.WriteFile(fixture.environment, []byte("PAM_NATIVE_FRESH=primary\n"), 0600))
	script := filepath.Join(root, "count-auth")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nprintf 'auth\\n' >> "+fixture.authCalls+"\n"), 0700))
	policy := fmt.Sprintf("auth required pam_exec.so %s\nauth required pam_unix.so\naccount required pam_unix.so\naccount required pam_access.so accessfile=%s\naccount required %s %s\n", script, fixture.access, module, fixture.environment)
	path := filepath.Join("/etc/pam.d", fixture.service)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	require.NoError(t, err)
	_, writeErr := file.WriteString(policy)
	require.NoError(t, file.Close())
	require.NoError(t, writeErr)
	t.Cleanup(func() { require.NoError(t, os.Remove(path)) })
	return fixture
}

func (this nativePamFixture) configure(t *testing.T, optIn bool) func(*configuration.Configuration) {
	t.Helper()
	return func(conf *configuration.Configuration) {
		local := &configuration.AuthorizationLocal{}
		require.NoError(t, local.SetDefaults())
		local.PamService = this.service
		conf.Flows[0].Authorization.RememberMe = configuration.RememberMeForbidden
		if optIn {
			conf.Flows[0].Authorization.RememberMe = configuration.RememberMeAllowed
		}
		local.Password.Allowed = template.BoolOf(true)
		local.Password.InteractiveAllowed = template.BoolOf(true)
		conf.Flows[0].Authorization.V = local
		conf.Flows[0].DiscoverAsSlug = "Work"
	}
}

func (this nativePamFixture) authCount(t *testing.T) int {
	t.Helper()
	raw, err := os.ReadFile(this.authCalls)
	require.NoError(t, err)
	return strings.Count(string(raw), "auth\n")
}

func nativePamPrimary(t *testing.T, handler http.Handler, method string) string {
	t.Helper()
	if method == "password" {
		return webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	}
	attempt := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
	step := waitWebLoginStep(t, handler, attempt, "Work")
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, attempt, "Work", step, "correct").Code)
	return webTestToken(t, finishWebAttempt(t, handler, attempt, "Work"))
}

func TestLinuxPamRememberMeActualHttpsNativePolicy(t *testing.T) {
	for _, method := range []string{"password", "keyboard-interactive"} {
		t.Run(method, func(t *testing.T) {
			native := nativePamTestFixture(t)
			configure := native.configure(t, true)
			fixture := newWebSocketFixture(t, webSocketWaitTask, configure)
			handler := localRememberHTTPSHandler(t, fixture)
			primary := nativePamPrimary(t, handler, method)
			key, public := rememberTestKey(t)
			binding := rememberTestEnroll(t, handler, primary, public, key)
			original := webTestAccess(t, fixture.svc, primary, "Work")
			require.Equal(t, "primary", original.auth.EnvVars()["PAM_NATIVE_FRESH"])
			beforeCalls := native.authCount(t)
			require.Equal(t, 1, beforeCalls)
			require.NoError(t, os.WriteFile(native.environment, []byte("PAM_NATIVE_FRESH=resumed\n"), 0600))
			resumed := rememberTestResume(t, handler, binding, key)
			access := webTestAccess(t, fixture.svc, resumed, "Work")
			require.Equal(t, binding.SessionID, access.auth.FindSession().Id().String())
			require.Equal(t, original.identity, access.identity)
			require.Equal(t, "resumed", access.auth.EnvVars()["PAM_NATIVE_FRESH"])
			require.Equal(t, beforeCalls, native.authCount(t), "resume must never run pam_authenticate or replay a password")
			store := access.auth.FindSession().(session.BrowserBindingSession)
			before, err := store.BrowserBindings(t.Context())
			require.NoError(t, err)
			fixture.svc.Configuration.Flows[0].Authorization.RememberMe = configuration.RememberMeForbidden
			challenge := rememberTestStart(t, handler, "resume", "", binding.selector())
			require.Equal(t, http.StatusUnauthorized, rememberTestProve(t, handler, challenge, key).Code, "current opt-out must deny previously enrolled bindings")
			fixture.svc.Configuration.Flows[0].Authorization.RememberMe = configuration.RememberMeAllowed
			challenge = rememberTestStart(t, handler, "resume", "", binding.selector())
			require.NoError(t, os.WriteFile(native.access, []byte("- : ALL : ALL\n"), 0600))
			require.Equal(t, http.StatusUnauthorized, rememberTestProve(t, handler, challenge, key).Code, "PAM account rejection after challenge must prevent resume")
			after, err := store.BrowserBindings(t.Context())
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, beforeCalls, native.authCount(t), "rejected account-only claims must not invoke authentication")
			require.Equal(t, http.StatusUnauthorized, webTestPassword(handler, "alice", "correct", "Work").Code, "primary login must also enforce the native account stack")
			require.NoError(t, os.WriteFile(native.access, []byte("+ : ALL : ALL\n"), 0600))
			challenge = rememberTestStart(t, handler, "resume", "", binding.selector())
			output, err := exec.CommandContext(t.Context(), "usermod", "--lock", "alice").CombinedOutput()
			require.NoError(t, err, "%s", output)
			require.Equal(t, http.StatusUnauthorized, rememberTestProve(t, handler, challenge, key).Code, "password lock must not be bypassed by PAM account success")
			after, err = store.BrowserBindings(t.Context())
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, beforeCalls+1, native.authCount(t), "only the explicit primary login may invoke authentication again")
			require.Equal(t, http.StatusNoContent, webTestRequest(handler, "POST", "app.example.org", webAPI+"logout", `{"slug":"Work"}`, resumed).Code)
			info, err := access.auth.FindSession().Info(t.Context())
			require.NoError(t, err)
			require.NotEqual(t, session.StateDisposed, info.State())
		})
	}
}

func TestLinuxPamRememberMeRejectsUnprovenOwnerAfterServiceRestart(t *testing.T) {
	for _, method := range []string{"password", "keyboard-interactive"} {
		t.Run(method, func(t *testing.T) {
			native := nativePamTestFixture(t)
			first := newWebSocketFixture(t, webSocketWaitTask, native.configure(t, true))
			handler := localRememberHTTPSHandler(t, first)
			primary := nativePamPrimary(t, handler, method)
			key, public := rememberTestKey(t)
			binding := rememberTestEnroll(t, handler, primary, public, key)
			oldSession := webTestAccess(t, first.svc, primary, "Work").auth.FindSession()
			owner := runtimePersistenceOwner(t, first.svc, oldSession)
			before, err := oldSession.(session.BrowserBindingSession).BrowserBindings(t.Context())
			require.NoError(t, err)
			beforeCalls := native.authCount(t)
			require.Equal(t, 1, beforeCalls)
			previous := first.svc.generation.snapshot.Configuration()
			require.NoError(t, first.svc.environments.(*executionTestRepository).shutdown())
			second := newWebSocketFixture(t, webSocketWaitTask, func(conf *configuration.Configuration) {
				// Keep every owner-relevant definition unchanged: rejection must
				// come from the unproven native provider, not new audit paths.
				conf.Session, conf.Flows, conf.Auditlogs = previous.Session, previous.Flows, previous.Auditlogs
			})
			handler = localRememberHTTPSHandler(t, second)
			require.Equal(t, http.StatusUnauthorized, webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, primary).Code)
			require.Equal(t, http.StatusUnauthorized, rememberTestRequest(handler, "resume", "", binding.selector()).Code)
			require.Equal(t, beforeCalls, native.authCount(t), "rejected ownership must not invoke PAM authentication")
			require.Nil(t, second.svc.runtime.sessionOwner(oldSession))
			preserved, err := second.svc.sessions.FindBy(t.Context(), oldSession.Flow(), oldSession.Id(), nil)
			require.NoError(t, err)
			retainedOwner, err := preserved.(session.RuntimeOwnershipSession).RuntimeOwnership(t.Context())
			require.NoError(t, err)
			require.Equal(t, owner, retainedOwner, "rejected resumption must not reassign ownership")
			after, err := preserved.(session.BrowserBindingSession).BrowserBindings(t.Context())
			require.NoError(t, err)
			require.Equal(t, before, after, "rejected resumption must preserve old browser bindings")
			fresh := nativePamPrimary(t, handler, method)
			access := webTestAccess(t, second.svc, fresh, "Work")
			require.NotEqual(t, binding.SessionID, access.auth.FindSession().Id().String())
			runtimePersistenceOwner(t, second.svc, access.auth.FindSession())
			require.Equal(t, beforeCalls+1, native.authCount(t), "new ownership requires fresh primary authentication")
			require.Equal(t, 2, webSessionCount(t, second.svc), "unproven session metadata remains preserved")
		})
	}
}

func TestLinuxPamRememberMeDefaultOptOutRejectsEnrollment(t *testing.T) {
	native := nativePamTestFixture(t)
	fixture := newWebSocketFixture(t, webSocketWaitTask, native.configure(t, false))
	handler := localRememberHTTPSHandler(t, fixture)
	primary := nativePamPrimary(t, handler, "password")
	_, public := rememberTestKey(t)
	require.Equal(t, http.StatusForbidden, rememberTestRequest(handler, "enroll", primary, map[string]string{"slug": "Work", "publicKey": public}).Code)
	require.Equal(t, 1, native.authCount(t))
}

func TestLinuxPamSSHRememberMeUsesAccountChecksWithoutRepeatingAuth(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		t.Run(map[bool]string{false: "password", true: "interactive"}[interactive], func(t *testing.T) {
			native := nativePamTestFixture(t)
			server := newAuthorizedKeysTestServerWithUsernameAndConfiguration(t, "alice", "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
				native.configure(t, true)(conf)
				conf.Flows[0].DiscoverAsSlug = ""
				conf.Flows[0].Authorization.V.(*configuration.AuthorizationLocal).AuthorizedKeys = nil
			})
			client, err := dialSdkMigrationServerWithClientConfig(server, func(conf *ssh.ClientConfig) {
				primary := ssh.Password("correct")
				if interactive {
					primary = ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
						answers := make([]string, len(questions))
						for i := range answers {
							answers[i] = "correct"
						}
						return answers, nil
					})
				}
				conf.Auth = []ssh.AuthMethod{ssh.PublicKeys(server.signer), primary}
			})
			require.NoError(t, err)
			channel, err := client.NewSession()
			require.NoError(t, err)
			require.NoError(t, channel.Setenv("REMEMBER_ME", "yes"))
			_, err = channel.Output("remember")
			require.NoError(t, err)
			_ = channel.Close()
			require.NoError(t, client.Close())
			require.Equal(t, 1, native.authCount(t))
			returning, err := server.dial()
			require.NoError(t, err)
			require.NoError(t, returning.Close())
			require.Equal(t, 1, native.authCount(t), "remembered SSH access must not invoke pam_authenticate")
			require.NoError(t, os.WriteFile(native.access, []byte("- : ALL : ALL\n"), 0600))
			denied, err := server.dial()
			require.Error(t, err, "current PAM account denial must reject a remembered SSH key")
			if denied != nil {
				_ = denied.Close()
			}
			require.Equal(t, 1, native.authCount(t))
		})
	}
}

func TestBrowserLocalPamPasswordRememberMeUiAcrossProfileRestart(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_BROWSER_UI") != "1" {
		t.Skip("enable Chromium UI coverage explicitly")
	}
	native := nativePamTestFixture(t)
	testBrowserLoginUi(t, true, "local-password-profile", native.configure(t, true))
}

func TestBrowserLocalPamInteractiveRememberMeUiAcrossProfileRestart(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_BROWSER_UI") != "1" {
		t.Skip("enable Chromium UI coverage explicitly")
	}
	native := nativePamTestFixture(t)
	testBrowserLoginUi(t, true, "local-interactive-profile", native.configure(t, true))
}
