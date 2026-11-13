//go:build linux

package service

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	buser "github.com/engity-com/bifroest/pkg/user"
)

func prepareLocalRememberTestRepository(t *testing.T) (*buser.EtcColonRepository, string) {
	t.Helper()
	root := t.TempDir()
	hash, err := sha512_crypt.New().Generate([]byte("correct"), []byte("$6$nativefixture$"))
	require.NoError(t, err)
	today := time.Now().Unix() / (24 * 60 * 60)
	shadow := fmt.Sprintf("alice:%s:%d:0:99999::::\n", hash, today-10)
	for file, value := range map[string]string{
		"passwd": "alice:x:1001:1001:Alice:/home/alice:/bin/sh\n",
		"group":  "primary:x:1001:\n",
		"shadow": shadow,
	} {
		require.NoError(t, os.WriteFile(filepath.Join(root, file), []byte(value), 0600))
	}
	repository := &buser.EtcColonRepository{PasswdFilename: filepath.Join(root, "passwd"), GroupFilename: filepath.Join(root, "group"), ShadowFilename: filepath.Join(root, "shadow"), FileSystemSyncThreshold: time.Hour}
	previous := buser.DefaultRepositoryProvider
	buser.DefaultRepositoryProvider = &buser.SharedRepositoryProvider[*buser.EtcColonRepository]{V: repository}
	t.Cleanup(func() { buser.DefaultRepositoryProvider = previous })
	return repository, shadow
}

func localRememberTestConfiguration(t *testing.T) func(*configuration.Configuration) {
	t.Helper()
	return func(conf *configuration.Configuration) {
		local := &configuration.AuthorizationLocal{}
		require.NoError(t, local.SetDefaults())
		local.PamService = ""
		local.Password.Allowed = template.BoolOf(true)
		local.Password.InteractiveAllowed = template.BoolOf(true)
		conf.Flows[0].Authorization.V = local
		conf.Flows[0].DiscoverAsSlug = "Work"
	}
}

func localRememberHTTPSHandler(t *testing.T, fixture *webSocketFixture) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := http.NewRequestWithContext(r.Context(), r.Method, "https://app.example.org"+r.URL.Path, r.Body)
		require.NoError(t, err)
		request.Header = r.Header.Clone()
		response, err := fixture.client.Do(request)
		require.NoError(t, err)
		defer response.Body.Close()
		require.Equal(t, 2, response.ProtoMajor)
		for name, values := range response.Header {
			w.Header()[name] = values
		}
		w.WriteHeader(response.StatusCode)
		_, err = io.Copy(w, response.Body)
		require.NoError(t, err)
	})
}

func TestLocalRepositoryRememberMeUsesActualHttpsAndFreshNativeAccountPolicy(t *testing.T) {
	for _, method := range []string{"password", "keyboard-interactive"} {
		t.Run(method, func(t *testing.T) {
			repository, shadow := prepareLocalRememberTestRepository(t)
			fixture := newWebSocketFixture(t, webSocketWaitTask, localRememberTestConfiguration(t))
			handler := localRememberHTTPSHandler(t, fixture)
			primary := ""
			if method == "password" {
				primary = fixture.login(t)
			} else {
				attempt := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
				step := waitWebLoginStep(t, handler, attempt, "Work")
				require.Equal(t, http.StatusAccepted, answerWebStep(handler, attempt, "Work", step, "correct").Code)
				primary = webTestToken(t, finishWebAttempt(t, handler, attempt, "Work"))
			}
			key, public := rememberTestKey(t)
			binding := rememberTestEnroll(t, handler, primary, public, key)
			resumed := rememberTestResume(t, handler, binding, key)
			access := webTestAccess(t, fixture.svc, resumed, "Work")
			require.Equal(t, "local", access.credential.Kind)
			require.Equal(t, method, access.credential.Method)
			require.Equal(t, "1001", access.identity.Subject)
			require.Equal(t, binding.SessionID, access.auth.FindSession().Id().String())
			require.Equal(t, 1, webSessionCount(t, fixture.svc))
			conn := fixture.dial(t)
			require.NoError(t, conn.WriteJSON(webSocketOpen(resumed)))
			requireWebSocketReady(t, conn)
			store := access.auth.FindSession().(session.BrowserBindingSession)
			before, err := store.BrowserBindings(t.Context())
			require.NoError(t, err)
			// Issue the proof challenge before locking the account. The later
			// claim must inspect native state, not the challenge-time/cache state.
			challenge := rememberTestStart(t, handler, "resume", "", binding.selector())
			require.NoError(t, os.WriteFile(repository.ShadowFilename, []byte(strings.Replace(shadow, "alice:", "alice:!", 1)), 0600))
			require.Equal(t, http.StatusUnauthorized, rememberTestProve(t, handler, challenge, key).Code)
			after, err := store.BrowserBindings(t.Context())
			require.NoError(t, err)
			require.Equal(t, before, after, "rejected proof must not slide or rewrite the binding")
			require.Equal(t, http.StatusNoContent, webTestRequest(handler, http.MethodPost, "app.example.org", webAPI+"logout", `{"slug":"Work"}`, resumed).Code)
			_, _, err = conn.ReadMessage()
			require.Error(t, err)
			requireWebSocketsDrained(t, fixture.svc)
			info, err := access.auth.FindSession().Info(t.Context())
			require.NoError(t, err)
			require.NotEqual(t, session.StateDisposed, info.State())
		})
	}
}

func TestLocalRepositoryRememberMeSurvivesServiceRestartWithoutPrimaryCredentials(t *testing.T) {
	_, _ = prepareLocalRememberTestRepository(t)
	configure := localRememberTestConfiguration(t)
	first := newWebSocketFixture(t, webSocketWaitTask, configure)
	key, public := rememberTestKey(t)
	primary := first.login(t)
	binding := rememberTestEnroll(t, localRememberHTTPSHandler(t, first), primary, public, key)
	storage := first.svc.Configuration.Session.V.(*configuration.SessionFs).Storage
	require.NoError(t, first.svc.environments.(*executionTestRepository).shutdown())
	second := newWebSocketFixture(t, webSocketWaitTask, func(conf *configuration.Configuration) {
		configure(conf)
		conf.Session.V.(*configuration.SessionFs).Storage = storage
	})
	handler := localRememberHTTPSHandler(t, second)
	require.Equal(t, http.StatusUnauthorized, webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, primary).Code)
	resumed := rememberTestResume(t, handler, binding, key)
	access := webTestAccess(t, second.svc, resumed, "Work")
	require.Equal(t, binding.SessionID, access.auth.FindSession().Id().String())
	require.Equal(t, 1, webSessionCount(t, second.svc))
}

func TestBrowserLocalRepositoryPasswordRememberMeUiAcrossProfileRestart(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_BROWSER_UI") != "1" {
		t.Skip("set BIFROEST_TEST_BROWSER_UI=1 after frontend build and Chromium installation")
	}
	_, _ = prepareLocalRememberTestRepository(t)
	testBrowserLoginUi(t, true, "local-password-profile", localRememberTestConfiguration(t))
}

func TestBrowserLocalRepositoryInteractiveRememberMeUiAcrossProfileRestart(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_BROWSER_UI") != "1" {
		t.Skip("set BIFROEST_TEST_BROWSER_UI=1 after frontend build and Chromium installation")
	}
	_, _ = prepareLocalRememberTestRepository(t)
	testBrowserLoginUi(t, true, "local-interactive-profile", localRememberTestConfiguration(t))
}
