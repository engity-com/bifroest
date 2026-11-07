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
		local.PamAccountResumeAllowed = optIn
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

func TestLinuxPamRememberMeActualHttpsNativePolicyAndRestart(t *testing.T) {
	for _, method := range []string{"password", "keyboard-interactive"} {
		t.Run(method, func(t *testing.T) {
			native := nativePamTestFixture(t)
			configure := native.configure(t, true)
			first := newWebSocketFixture(t, webSocketWaitTask, configure)
			handler := localRememberHTTPSHandler(t, first)
			primary := nativePamPrimary(t, handler, method)
			key, public := rememberTestKey(t)
			binding := rememberTestEnroll(t, handler, primary, public, key)
			original := webTestAccess(t, first.svc, primary, "Work")
			require.Equal(t, "primary", original.auth.EnvVars()["PAM_NATIVE_FRESH"])
			beforeCalls := native.authCount(t)
			require.Equal(t, 1, beforeCalls)
			require.NoError(t, os.WriteFile(native.environment, []byte("PAM_NATIVE_FRESH=resumed\n"), 0600))
			storage := first.svc.Configuration.Session.V.(*configuration.SessionFs).Storage
			require.NoError(t, first.svc.environments.(*executionTestRepository).shutdown())
			second := newWebSocketFixture(t, webSocketWaitTask, func(conf *configuration.Configuration) {
				configure(conf)
				conf.Session.V.(*configuration.SessionFs).Storage = storage
			})
			handler = localRememberHTTPSHandler(t, second)
			resumed := rememberTestResume(t, handler, binding, key)
			access := webTestAccess(t, second.svc, resumed, "Work")
			require.Equal(t, binding.SessionID, access.auth.FindSession().Id().String())
			require.Equal(t, original.identity, access.identity)
			require.Equal(t, "resumed", access.auth.EnvVars()["PAM_NATIVE_FRESH"])
			require.Equal(t, beforeCalls, native.authCount(t), "resume after service restart must never run pam_authenticate or replay a password")
			store := access.auth.FindSession().(session.BrowserBindingSession)
			before, err := store.BrowserBindings(t.Context())
			require.NoError(t, err)
			local := second.svc.Configuration.Flows[0].Authorization.V.(*configuration.AuthorizationLocal)
			local.PamAccountResumeAllowed = false
			challenge := rememberTestStart(t, handler, "resume", "", binding.selector())
			require.Equal(t, http.StatusUnauthorized, rememberTestProve(t, handler, challenge, key).Code, "current opt-out must deny previously enrolled bindings")
			local.PamAccountResumeAllowed = true
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

func TestLinuxPamRememberMeDefaultOptOutRejectsEnrollment(t *testing.T) {
	native := nativePamTestFixture(t)
	fixture := newWebSocketFixture(t, webSocketWaitTask, native.configure(t, false))
	handler := localRememberHTTPSHandler(t, fixture)
	primary := nativePamPrimary(t, handler, "password")
	key, public := rememberTestKey(t)
	challenge := rememberTestStart(t, handler, "enroll", primary, map[string]string{"slug": "Work", "publicKey": public})
	require.Equal(t, http.StatusUnauthorized, rememberTestProve(t, handler, challenge, key).Code)
	require.Equal(t, 1, native.authCount(t))
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
