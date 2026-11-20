package service

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/https"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

func TestBrowserOidcCodeRedirectWithRealCookies(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_BROWSER_CLIENT") != "1" {
		t.Skip("set BIFROEST_TEST_BROWSER_CLIENT=1 after building web/ and installing Chromium")
	}
	t.Run("WebUI", func(t *testing.T) { browserOidcCode(t, false, "") })
	t.Run("WebUI-popup-blocked", func(t *testing.T) { browserOidcCode(t, false, "blocked") })
	t.Run("WebUI-named", func(t *testing.T) { browserOidcCode(t, false, "named") })
	t.Run("WebUI-forwarded-ticket", func(t *testing.T) { browserOidcCode(t, false, "forwarded") })
	t.Run("SSH", func(t *testing.T) { browserOidcCode(t, true, "") })
	t.Run("SSH-login-only", func(t *testing.T) { browserOidcCode(t, true, "login-only") })
}

func browserOidcCode(t *testing.T, isSSH bool, mode string) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	customJS := filepath.Join(t.TempDir(), "custom.js")
	customCSS := filepath.Join(t.TempDir(), "custom.css")
	require.NoError(t, os.WriteFile(customJS, []byte(`window.oidcCustomEvents = []; addEventListener('bifroest:configure', ({detail}) => { window.oidcCustomEvents.push('configure'); detail.title = 'Fixture sign-in'; }); addEventListener('bifroest:ready', () => window.oidcCustomEvents.push('ready'));`), 0600))
	require.NoError(t, os.WriteFile(customCSS, []byte(`.bifroest-login-card { --login-custom-check: applied; }`), 0600))
	svc, _, p, _ := oidcCodeFixture(t, func(conf *configuration.Configuration, _ *oidcCodeProvider) {
		conf.Http.Addresses = bnet.NetAddresses{bnet.MustNewAddress(listener.Addr().String())}
		conf.Http.CustomJs, conf.Http.CustomCss = []string{customJS}, []string{customCSS}
		conf.Http.CustomHtmlBody = `<span hidden id="custom-login-body">Operator content</span>`
		if mode == "login-only" {
			conf.Http.WebUi.Enabled = new(false)
		}
		if mode == "named" {
			conf.Flows[0].Http.RequestUser = commonBool(true)
			conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		}
	})
	navigations := make(chan [3]string, 4)
	endpoint, err := https.NewEndpoint(svc.Configuration.Http, https.EndpointOptions{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSSH && r.Method == http.MethodGet && r.URL.Path == "/login/" {
			select {
			case navigations <- [3]string{r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Sec-Fetch-Mode"), r.Header.Get("Sec-Fetch-Dest")}:
			default:
			}
		}
		svc.web.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, p.server.Client())))
	})})
	require.NoError(t, err)
	require.NoError(t, endpoint.Prepare(t.Context()))
	done := make(chan error, 1)
	go func() { done <- endpoint.Serve(listener) }()
	t.Cleanup(func() {
		require.NoError(t, endpoint.Close())
		select {
		case err := <-done:
			require.ErrorIs(t, err, http.ErrServerClosed)
		case <-time.After(3 * time.Second):
			t.Error("OIDC HTTPS test endpoint did not stop")
		}
	})
	node := os.Getenv("BIFROEST_TEST_NODE")
	if node == "" {
		node, err = exec.LookPath("node")
		require.NoError(t, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	code := svc.Configuration.Flows[0].Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode)
	arguments := []string{filepath.Join(root, "web", "test", "https-oidc.ts"), code.Origin()}
	if mode != "" && mode != "login-only" {
		arguments = append(arguments, mode)
	}
	if isSSH {
		address := serveOidcSSH(t, svc, p)
		messages := make(chan string, 4)
		connected := make(chan error, 1)
		go func() {
			client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: "alice", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 20 * time.Second, Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, instruction string, questions []string, _ []bool) ([]string, error) {
				messages <- instruction
				return make([]string, len(questions)), nil
			})}})
			if client != nil {
				_ = client.Close()
			}
			connected <- err
		}()
		select {
		case message := <-messages:
			link := regexp.MustCompile(`https://\S+`).FindString(message)
			comparison := regexp.MustCompile(`code "([3479CDFHJKMNPRTUVWXY]{2})"`).FindStringSubmatch(message)
			require.Len(t, comparison, 2)
			arguments = append(arguments, link, comparison[1])
		case <-ctx.Done():
			t.Fatal("no SSH login URL")
		}
		t.Cleanup(func() {
			select {
			case err := <-connected:
				require.NoError(t, err)
			case <-time.After(3 * time.Second):
				t.Error("SSH authentication did not finish")
			}
		})
	}
	command := exec.CommandContext(ctx, node, arguments...)
	command.Dir = filepath.Join(root, "web")
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	require.Contains(t, string(output), "PASS: real OIDC redirect")
	if isSSH {
		select {
		case headers := <-navigations:
			require.Equal(t, [3]string{"cross-site", "navigate", "document"}, headers, "the HTTPS server must see the real webmail navigation, not forged test headers")
		default:
			t.Fatal("no SSH login document navigation observed")
		}
	}
	if mode == "forwarded" {
		require.Zero(t, p.logins.Load())
		require.Zero(t, webSessionCount(t, svc))
		return
	}
	require.EqualValues(t, 1, p.logins.Load())
	require.Equal(t, 1, webSessionCount(t, svc))
}
