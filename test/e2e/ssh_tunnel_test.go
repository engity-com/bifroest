//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type tunnelPKI struct{ ca, cert, key string }

func newTunnelPKI(t *testing.T, directory string) tunnelPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Bifroest tunnel E2E CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	require.NoError(t, err)
	root, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, root, key)
	require.NoError(t, err)
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crl)
	}))
	t.Cleanup(crlServer.Close)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CRLDistributionPoints: []string{crlServer.URL + "/ca.crl"}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, key)
	require.NoError(t, err)
	private, err := x509.MarshalPKCS8PrivateKey(leafKey)
	require.NoError(t, err)
	result := tunnelPKI{filepath.Join(directory, "ca.pem"), filepath.Join(directory, "https.pem"), filepath.Join(directory, "https-key.pem")}
	require.NoError(t, os.WriteFile(result.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	require.NoError(t, os.WriteFile(result.cert, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...), 0600))
	require.NoError(t, os.WriteFile(result.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600))
	return result
}

func reserveTunnelPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	require.NoError(t, l.Close())
	return port
}

type tunnelClient struct {
	ssh, sftp, curl string
	windows         bool
	directory       string
}

func (c tunnelClient) path(t *testing.T, path string) string {
	t.Helper()
	if !c.windows {
		return path
	}
	if c.directory != "" && !strings.HasSuffix(strings.ToLower(path), ".exe") {
		target := filepath.Join(c.directory, filepath.Base(path))
		if data, err := os.ReadFile(path); err == nil {
			require.NoError(t, os.WriteFile(target, data, 0600))
		} else {
			require.True(t, os.IsNotExist(err), err)
		}
		path = target
	}
	result := runCommand(t.Context(), "", nil, "wslpath", "-w", path)
	require.NoError(t, result.err, result.stderr)
	return strings.ReplaceAll(strings.TrimSpace(result.stdout), `\`, "/")
}

func windowsTunnelDirectory(t *testing.T) string {
	t.Helper()
	// Keep Windows OpenSSH files on NTFS with an explicit, user-only ACL.
	// The Linux /tmp path may not be accessible through WSL's Windows share.
	script := `$ErrorActionPreference='Stop'; $p=Join-Path $env:TEMP ('bifroest-tunnel-'+[guid]::NewGuid().ToString('N')); $d=New-Item -ItemType Directory -Path $p; $a=Get-Acl -LiteralPath $p; $a.SetAccessRuleProtection($true,$false); $r=New-Object System.Security.AccessControl.FileSystemAccessRule([System.Security.Principal.WindowsIdentity]::GetCurrent().Name,'FullControl','ContainerInherit,ObjectInherit','None','Allow'); $a.AddAccessRule($r); Set-Acl -LiteralPath $p -AclObject $a; $p`
	result := runCommand(t.Context(), "", nil, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	require.NoError(t, result.err, result.stderr)
	converted := runCommand(t.Context(), "", nil, "wslpath", "-u", strings.TrimSpace(result.stdout))
	require.NoError(t, converted.err, converted.stderr)
	directory := strings.TrimSpace(converted.stdout)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(directory)) })
	return directory
}

func tunnelCommand(t *testing.T, c tunnelClient, mode, port, ca string) string {
	t.Helper()
	quote := func(value string) string {
		if c.windows {
			return `"` + value + `"`
		}
		return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
	}
	args := []string{c.path(t, c.curl), "-q", "-fsSN", "--no-progress-meter", "--noproxy", "*", "-T", ".", "-H", "Expect:", "-H", "X-Forwarded-For: 198.51.100.1", "--cacert", c.path(t, ca)}
	scheme := "https"
	if mode == "wss" {
		args = append(args, "--http1.1", "-X", "GET")
		scheme = "wss"
	} else {
		version := "--http1.1"
		if mode == "https2" {
			version = "--http2-prior-knowledge"
		}
		args = append(args, version, "-X", "POST", "-H", "Content-Type: application/octet-stream")
	}
	args = append(args, scheme+"://%h:"+port+"/api/v1/ssh")
	for index := range args {
		args[index] = quote(args[index])
	}
	return strings.Join(args, " ")
}

func (c tunnelClient) args(t *testing.T, f *fixture, proxy, identity, knownHosts string) []string {
	t.Helper()
	null := "/dev/null"
	if c.windows {
		null = "NUL"
	}
	return []string{"-F", null, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", c.path(t, identity), "-o", `UserKnownHostsFile="` + c.path(t, knownHosts) + `"`, "-o", "GlobalKnownHostsFile=" + null, "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=bifroest-tunnel", "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=1", "-o", "ServerAliveCountMax=2", "-o", "LogLevel=ERROR", "-o", "ProxyCommand=" + proxy}
}

func runTunnelClient(t *testing.T, executable string, input []byte, args ...string) commandResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.WaitDelay = time.Second
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return commandResult{stdout.String(), stderr.String(), err}
}

func TestOpenSSHTunnel(t *testing.T) {
	f, err := newFixture(t)
	require.NoError(t, err)
	require.NoError(t, f.prepareRuntime(false), "a real backend is required; do not silently skip the tunnel suite")
	targetPort, targetHosts, err := f.prepareSSHEnvironmentTarget(f.hostKey, f.clientKey)
	require.NoError(t, err)
	// Apply the tunnel peer restriction after the backend copied its own key.
	key := mustRead(f.clientKey + ".pub")
	require.NoError(t, os.WriteFile(f.clientKey+".pub", append([]byte(`from="127.0.0.1" `), key...), 0600))
	pki := newTunnelPKI(t, f.tempDir)
	httpPort := reserveTunnelPort(t)
	f.port = reserveTunnelPort(t)
	configuration := fmt.Sprintf(sshEnvironmentRecordingConfiguration, "", yamlString("127.0.0.1:"+f.port), yamlString(f.hostKey), yamlString(f.sessionStorage), yamlString(f.clientKey+".pub"), yamlString("127.0.0.1:"+targetPort), yamlString(targetHosts), yamlString(f.clientKey), true, "      reversePortForwardingAllowed: true\n", "")
	configuration = strings.Replace(configuration, "ssh:\n", "ssh:\n  enabled: false\n  proxyProtocol: true\n", 1)
	configuration += fmt.Sprintf(`
http:
  enabled: true
  addresses: ['127.0.0.1:%s']
  domains: [127.0.0.1]
  webUi: {enabled: false}
  loginFlow: {enabled: false}
  readHeaderTimeout: 500ms
  gracefulShutdownTimeout: 100ms
  tls:
    certificates:
      - certificateFile: %s
        privateKeyFile: %s
`, httpPort, yamlString(pki.cert), yamlString(pki.key))
	configFile := filepath.Join(f.tempDir, "tunnel.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte(configuration), 0600))
	f.bifroestProc, err = f.launchLoggedProcess("bifroest-tunnel", nil, f.bifroest, "run", "--configuration="+configFile, "--log.level=DEBUG")
	require.NoError(t, err)
	require.NoError(t, pollProcess(10*time.Second, f.bifroestProc, func() error {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+httpPort, time.Second)
		if c != nil {
			_ = c.Close()
		}
		return err
	}))
	direct, err := net.DialTimeout("tcp", "127.0.0.1:"+f.port, time.Second)
	if direct != nil {
		_ = direct.Close()
	}
	require.Error(t, err, "ssh.enabled=false must not bind the TCP port")
	keyFields := strings.Fields(string(mustRead(f.hostKey + ".pub")))
	require.NoError(t, os.WriteFile(f.knownHosts, []byte("bifroest-tunnel "+strings.Join(keyFields[:2], " ")+"\n"), 0600))
	wrongHosts := filepath.Join(f.tempDir, "wrong-known-hosts")
	wrongFields := strings.Fields(string(mustRead(f.wrongKey + ".pub")))
	require.NoError(t, os.WriteFile(wrongHosts, []byte("bifroest-tunnel "+strings.Join(wrongFields[:2], " ")+"\n"), 0600))
	echo, err := f.launchLoggedProcess("tunnel-echo", nil, f.runtimeCLI, "exec", f.containerID, "/usr/local/bin/e2e-helper", "echo-server", "tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	require.NoError(t, err)
	t.Cleanup(echo.stop)
	require.NoError(t, pollProcess(5*time.Second, echo, func() error {
		if strings.Contains(echo.stdout.String(), fmt.Sprintf(":%d", echoPort)) {
			return nil
		}
		return fmt.Errorf("echo server is not ready")
	}))
	curl, err := exec.LookPath("curl")
	require.NoError(t, err)
	clients := []tunnelClient{{ssh: f.tools["ssh"], sftp: f.tools["sftp"], curl: curl}}
	if runtime.GOOS == "linux" && os.Getenv("WSL_INTEROP") != "" {
		ssh, err := exec.LookPath("ssh.exe")
		require.NoError(t, err)
		sftp, err := exec.LookPath("sftp.exe")
		require.NoError(t, err)
		curl, err := exec.LookPath("curl.exe")
		require.NoError(t, err)
		clients = append(clients, tunnelClient{ssh: ssh, sftp: sftp, curl: curl, windows: true, directory: windowsTunnelDirectory(t)})
	}
	for _, client := range clients {
		t.Run(filepath.Base(client.ssh), func(t *testing.T) {
			version := runTunnelClient(t, client.ssh, nil, "-V")
			t.Logf("%s%s", version.stdout, version.stderr)
			require.Equal(t, client.windows, strings.Contains(version.stdout+version.stderr, "Windows"), "client family must match the actual executable")
			modes := []string{"https1", "wss"}
			if !client.windows {
				modes = append(modes, "https2")
			}
			for _, mode := range modes {
				t.Run(mode, func(t *testing.T) {
					if client.windows && mode == "wss" && os.Getenv("BIFROEST_TEST_TUNNEL_WINDOWS_WSS") != "1" {
						t.Skip("Windows curl 8.22.0/Schannel corrupts concurrent WSS streams in the independent curl probe; set BIFROEST_TEST_TUNNEL_WINDOWS_WSS=1 to require this profile with another/fixed build")
					}
					proxy := tunnelCommand(t, client, mode, httpPort, pki.ca)
					args := client.args(t, f, proxy, f.clientKey, f.knownHosts)
					streams := runTunnelClient(t, client.ssh, nil, append(append([]string{}, args...), "e2e@127.0.0.1", "/usr/local/bin/e2e-helper streams")...)
					require.Equal(t, 23, exitCode(streams.err), streams.stderr)
					require.Equal(t, "stdout-e2e\n", streams.stdout)
					require.Equal(t, "stderr-e2e\n", streams.stderr)
					payload := streamPayload(3 << 20)
					binary := runTunnelClient(t, client.ssh, payload, append(append([]string{}, args...), "e2e@127.0.0.1", "/usr/local/bin/e2e-helper stream-duplex 3145728")...)
					require.NoError(t, binary.err, binary.stderr)
					require.Equal(t, string(append(payload, []byte("ok\n")...)), binary.stdout)
					idle := runTunnelClient(t, client.ssh, nil, append(append([]string{}, args...), "e2e@127.0.0.1", "/usr/local/bin/e2e-helper exit-after 2500 0")...)
					require.NoError(t, idle.err, idle.stderr)
					wrong := runTunnelClient(t, client.ssh, nil, append(client.args(t, f, proxy, f.wrongKey, f.knownHosts), "e2e@127.0.0.1", "true")...)
					require.Equal(t, 255, exitCode(wrong.err), "wrong SSH key must fail")
					wrongHost := runTunnelClient(t, client.ssh, nil, append(client.args(t, f, proxy, f.clientKey, wrongHosts), "e2e@127.0.0.1", "true")...)
					require.Equal(t, 255, exitCode(wrongHost.err), "wrong SSH host key must fail")
					require.Empty(t, wrongHost.stdout)
					runTunnelSftp(t, f, client, args, mode, payload)
					forward := runTunnelClient(t, client.ssh, payload[:256<<10], append(append([]string{}, args...), "-W", fmt.Sprintf("127.0.0.1:%d", echoPort), "e2e@127.0.0.1")...)
					require.NoError(t, forward.err, forward.stderr)
					require.Equal(t, string(payload[:256<<10]), forward.stdout)
					runTunnelReverseForward(t, f, client, args)
				})
			}
		})
	}
}

func runTunnelReverseForward(t *testing.T, f *fixture, client tunnelClient, args []string) {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = c.SetDeadline(time.Now().Add(10 * time.Second)); _, _ = io.Copy(c, c) }()
		}
	}()
	forward := fmt.Sprintf("127.0.0.1:%d:%s", reversePort, echo.Addr())
	process := startProcess(t, nil, client.ssh, append(append([]string{}, args...), "-N", "-o", "ExitOnForwardFailure=yes", "-R", forward, "e2e@127.0.0.1")...)
	defer process.stop()
	require.NoError(t, pollProcess(10*time.Second, process, func() error {
		result := f.runtime(5*time.Second, "exec", f.containerID, "/usr/local/bin/e2e-helper", "echo-client", "tcp", fmt.Sprintf("127.0.0.1:%d", reversePort), "262144")
		if result.err != nil {
			return fmt.Errorf("reverse forward: %w: %s", result.err, result.stderr)
		}
		if result.stdout != "ok 262144\n" {
			return fmt.Errorf("reverse forward output: %q", result.stdout)
		}
		return nil
	}))
}

func runTunnelSftp(t *testing.T, f *fixture, client tunnelClient, args []string, mode string, payload []byte) {
	t.Helper()
	input := filepath.Join(f.tempDir, "sftp-"+mode+"-input")
	output := filepath.Join(f.tempDir, "sftp-"+mode+"-output")
	require.NoError(t, os.WriteFile(input, payload, 0600))
	// SFTP's command parser treats backslashes as escapes, including on Windows.
	local := func(path string) string { return strings.ReplaceAll(client.path(t, path), `\`, "/") }
	remote := "/tmp/" + f.name + "-" + mode
	batch := fmt.Sprintf("put \"%s\" %s\nget %s \"%s\"\nrm %s\n", local(input), remote, remote, local(output), remote)
	ssh := client.ssh
	if client.windows {
		ssh = client.path(t, ssh)
	}
	result := runTunnelClient(t, client.sftp, []byte(batch), append(append([]string{}, args...), "-S", ssh, "-b", "-", "e2e@127.0.0.1")...)
	require.NoError(t, result.err, result.stderr)
	if client.windows {
		output = filepath.Join(client.directory, filepath.Base(output))
	}
	require.Equal(t, payload, mustRead(output))
}
