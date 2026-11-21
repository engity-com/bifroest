//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestMonitoringManagementCLI(t *testing.T) {
	root, err := findRepoRoot()
	require.NoError(t, err)
	goTool, err := findGoTool(root)
	require.NoError(t, err)
	dir := t.TempDir()
	binary := filepath.Join(dir, "bifroest")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	build := runCommand(ctx, root, []string{"CGO_ENABLED=0", "GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH}, goTool, "build", "-p=1", "-o", binary, "./cmd/bifroest")
	cancel()
	require.NoError(t, build.err, build.stderr)
	newKey := func(name string) (string, gossh.Signer) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signer, err := gossh.NewSignerFromKey(private)
		require.NoError(t, err)
		der, err := x509.MarshalPKCS8PrivateKey(private)
		require.NoError(t, err)
		path := filepath.Join(dir, name)
		require.NoError(t, bfcrypto.WriteBootstrapFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), false))
		return path, signer
	}
	hostKey, hostSigner := newKey("host")
	identity, login := newKey("login")
	addresses := monitoringAddresses(t, 2)
	address, unusedMonitoring := addresses[0], addresses[1]
	confPath := filepath.Join(dir, "bifroest.yaml")
	monitoringJSONFile(t, confPath, map[string]any{
		"ssh":          map[string]any{"addresses": []string{address}, "keys": map[string]any{"hostKeys": []string{hostKey}}, "banner": ""},
		"monitoring":   map[string]any{"enabled": false, "addresses": []string{unusedMonitoring}, "bearerTokenFile": filepath.Join(dir, "missing-token"), "tls": map[string]any{"enabled": true, "certificates": []any{map[string]any{"certificateFile": filepath.Join(dir, "missing.crt"), "privateKeyFile": filepath.Join(dir, "missing.key")}}}},
		"session":      map[string]any{"type": "fs", "storage": filepath.Join(dir, "sessions")},
		"alternatives": map[string]any{"location": filepath.Join(dir, "alternatives")},
		"housekeeping": map[string]any{"initialDelay": "1h"},
		"flows":        []any{map[string]any{"name": "admin", "authorization": map[string]any{"type": "simple", "entries": []any{map[string]any{"name": "admin", "authorizedKeys": string(gossh.MarshalAuthorizedKey(login.PublicKey()))}}}, "environment": map[string]any{"type": "management"}}},
	})
	logPrefix := filepath.Join(root, "var", "e2e", fmt.Sprintf("monitoring-management-%d", time.Now().UnixNano()))
	server, err := launchProcessWithLogs(root, nil, logPrefix, binary, "run", "--configuration="+confPath)
	require.NoError(t, err)
	defer server.stop()
	var direct *gossh.Client
	require.NoError(t, pollProcess(20*time.Second, server, func() error {
		var err error
		direct, err = gossh.Dial("tcp", address, &gossh.ClientConfig{User: "admin", Auth: []gossh.AuthMethod{gossh.PublicKeys(login)}, HostKeyCallback: gossh.FixedHostKey(hostSigner.PublicKey()), Timeout: time.Second})
		return err
	}))
	defer direct.Close()
	conn, err := net.DialTimeout("tcp", unusedMonitoring, 500*time.Millisecond)
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err, "management-only collection must not open a monitoring listener")
	hosts := filepath.Join(dir, "known_hosts")
	require.NoError(t, os.WriteFile(hosts, []byte(knownhosts.Line([]string{knownhosts.Normalize(address)}, hostSigner.PublicKey())+"\n"), 0600))
	host, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	clientConfig := filepath.Join(dir, "ssh_config")
	require.NoError(t, os.WriteFile(clientConfig, []byte(fmt.Sprintf("Host metrics\n HostName %s\n Port %s\n User admin\n IdentityAgent none\n IdentityFile %q\n UserKnownHostsFile %q\n", host, port, filepath.ToSlash(identity), filepath.ToSlash(hosts))), 0600))
	for _, selected := range []string{"table", "json", "openmetrics"} {
		t.Run(selected, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			args := []string{"@metrics", "--sshConfig=" + clientConfig, "metrics", "show", "bifroest_connections_active", "bifroest_sessions_active"}
			if selected != "table" {
				args = append(args, "--format="+selected)
			}
			result := runCommand(ctx, root, nil, binary, args...)
			require.NoError(t, result.err, result.stderr)
			require.Contains(t, result.stdout, "bifroest_connections_active")
			require.Contains(t, result.stdout, "bifroest_sessions_active")
			require.NotContains(t, result.stdout, "bifroest_authentication_attempts_total")
			command, err := direct.NewSession()
			require.NoError(t, err)
			output, err := command.Output("metrics show bifroest_connections_active bifroest_sessions_active --format=" + selected)
			require.NoError(t, err)
			for _, data := range []string{result.stdout, string(output)} {
				switch selected {
				case "json":
					var snapshot struct {
						CapturedAt       time.Time         `json:"capturedAt"`
						ProcessStartedAt time.Time         `json:"processStartedAt"`
						Families         []json.RawMessage `json:"families"`
					}
					require.NoError(t, json.Unmarshal([]byte(data), &snapshot))
					require.Len(t, snapshot.Families, 2)
					require.False(t, snapshot.CapturedAt.IsZero())
					require.False(t, snapshot.ProcessStartedAt.IsZero())
				case "openmetrics":
					require.True(t, strings.HasSuffix(data, "# EOF\n"))
				default:
					require.Contains(t, data, "METRIC")
					require.Contains(t, data, "LABELS")
				}
			}
		})
	}
	for _, names := range [][]string{nil, {"bifroest_http_requests_total"}, {"unknown"}} {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		args := append([]string{"@metrics", "--sshConfig=" + clientConfig, "metrics", "show", "--format=json"}, names...)
		result := runCommand(ctx, root, nil, binary, args...)
		cancel()
		if len(names) > 0 && names[0] == "unknown" {
			require.Error(t, result.err)
			require.Empty(t, result.stdout)
			require.Contains(t, result.stderr, "unknown metric family")
		} else {
			require.NoError(t, result.err, result.stderr)
			if len(names) == 0 {
				require.Contains(t, result.stdout, "bifroest_authentication_attempts_total")
			} else {
				require.Contains(t, result.stdout, `"families":[]`)
			}
		}
	}
	// The default OpenMetrics path is not inferred: only the explicit plural form is accepted.
	command, err := direct.NewSession()
	require.NoError(t, err)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output("metrics show --format=openmetric")
	require.Error(t, err)
	require.Empty(t, output)
	t.Logf("both CLI/SSH paths passed without HTTP monitoring; logs: %s", logPrefix)
}
