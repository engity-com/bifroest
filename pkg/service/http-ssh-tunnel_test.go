package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/https"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

type sshTunnelFixture struct {
	svc           *service
	transport     *http.Transport
	address       string
	directAddress string
	cancel        context.CancelFunc
	await         func() error
	shutdown      *listenerShutdown
}

func newSshTunnelFixture(t *testing.T, direct, web, tunnel, login bool, configure func(*configuration.Configuration), environments ...*authorizedKeysTestEnvironment) *sshTunnelFixture {
	t.Helper()
	conf := httpListenerTestConfiguration(t)
	conf.Flows[0].Requirement.Http.IncludedSlug = common.MustNewRegexp("^work$")
	conf.Ssh.Enabled = new(direct)
	conf.Http.WebUi.Enabled, conf.Http.SshTunnel.Enabled, conf.Http.LoginFlow.Enabled = new(web), new(tunnel), new(login)
	conf.Http.Tls.Acme.Enabled = false
	conf.Ssh.GracefulShutdownTimeout = common.DurationOf(200 * time.Millisecond)
	if configure != nil {
		configure(&conf)
	}
	root := httpListenerTestCertificate(t, &conf, nil)
	svc := prepareHTTPListenerTestService(t, conf)
	if len(environments) > 0 {
		require.NoError(t, svc.environments.Close())
		svc.environments = &authorizedKeysTestRepository{environment: environments[0]}
	}
	ctx, cancel := context.WithCancel(context.Background())
	bound := make(chan net.Listener, 2)
	done := make(chan error, 1)
	var shutdown listenerShutdown
	go func() {
		var err error
		shutdown, err = svc.runListeners(ctx, func(address bnet.Address) (net.Listener, error) {
			listener, err := address.Listen()
			if err == nil {
				bound <- listener
			}
			return listener, err
		})
		done <- err
	}()
	await := awaitHTTPListenerTestRun(t, done)
	t.Cleanup(func() { cancel(); _ = await() })
	listener := <-bound
	var directAddress string
	if direct {
		directAddress = listener.Addr().String()
		listener = <-bound
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	require.Eventually(t, svc.https.Ready, 3*time.Second, time.Millisecond)
	if tunnel {
		require.Eventually(t, svc.sshTunnel.ready.Load, time.Second, time.Millisecond)
	}
	return &sshTunnelFixture{svc: svc, transport: transport, address: listener.Addr().String(), directAddress: directAddress, cancel: cancel, await: await, shutdown: &shutdown}
}

func (f *sshTunnelFixture) request(t *testing.T, method, path string, body io.Reader) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, method, "https://app.example.org"+path, body)
	require.NoError(t, err)
	if method == http.MethodPost {
		req.Header.Set("Origin", "https://app.example.org")
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := (&http.Client{Transport: f.transport}).Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func TestSshTunnelComponentRoutingCombinations(t *testing.T) {
	for mask := range 16 {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			f := newSshTunnelFixture(t, mask&1 != 0, mask&2 != 0, mask&4 != 0, mask&8 != 0, nil)
			api := f.request(t, "POST", "/api/v1/discovery", strings.NewReader(`{"slug":"work"}`))
			if mask&2 == 0 {
				require.Equal(t, 404, api.StatusCode)
			} else {
				require.NotEqual(t, 404, api.StatusCode)
			}
			login := f.request(t, "GET", "/login", nil)
			if mask&8 == 0 {
				require.Equal(t, 404, login.StatusCode)
			} else {
				require.NotEqual(t, 404, login.StatusCode)
			}
			tunnel := f.request(t, "GET", https.SshTunnelPath, nil)
			if mask&4 == 0 {
				require.Equal(t, 404, tunnel.StatusCode)
			} else {
				require.Equal(t, 405, tunnel.StatusCode)
			}
			if mask&2 == 0 {
				require.Equal(t, 404, f.request(t, "GET", "/assets/browser-key-worker.js", nil).StatusCode)
			}
			f.cancel()
			require.NoError(t, f.await())
		})
	}
}

type httpTunnelTestConn struct {
	net.Conn
	io.Reader
	io.Writer
	close     func() error
	closeOnce sync.Once
	closeErr  error
}

func (*httpTunnelTestConn) LocalAddr() net.Addr  { return tunnelAddr("test local") }
func (*httpTunnelTestConn) RemoteAddr() net.Addr { return tunnelAddr("test remote") }

func (c *httpTunnelTestConn) Read(data []byte) (int, error)  { return c.Reader.Read(data) }
func (c *httpTunnelTestConn) Write(data []byte) (int, error) { return c.Writer.Write(data) }
func (c *httpTunnelTestConn) Close() error {
	// Closing the WSS pipe wakes SSH's reader, which also closes this connection.
	// Serialize cleanup so the resulting second TLS close cannot mask its result.
	c.closeOnce.Do(func() { c.closeErr = c.close() })
	return c.closeErr
}

func TestHTTPTunnelTestConnConcurrentCloseRunsCleanupOnceAndPreservesErrors(t *testing.T) {
	for _, test := range []struct {
		name     string
		closeErr error
	}{
		{"success", nil},
		{"failure", errors.New("tunnel cleanup failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			conn := &httpTunnelTestConn{close: func() error {
				if calls.Add(1) > 1 {
					return net.ErrClosed
				}
				return test.closeErr
			}}
			const callers = 32
			start := make(chan struct{})
			results := make(chan error, callers)
			var workers sync.WaitGroup
			for range callers {
				workers.Go(func() {
					<-start
					results <- conn.Close()
				})
			}
			close(start)
			workers.Wait()
			close(results)
			for err := range results {
				require.Equal(t, test.closeErr, err, "concurrent SSH and fixture cleanup must share the first close result")
			}
			require.Equal(t, int32(1), calls.Load())
			require.Equal(t, test.closeErr, conn.Close(), "later fixture cleanup must preserve the original close result")
			require.Equal(t, int32(1), calls.Load())
		})
	}
}

func (f *sshTunnelFixture) transportConn(t *testing.T, mode string) net.Conn {
	t.Helper()
	var conn net.Conn
	switch mode {
	case "direct":
		var err error
		conn, err = net.DialTimeout("tcp", f.directAddress, time.Second)
		require.NoError(t, err)
		require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	case "wss":
		tlsConfig := f.transport.TLSClientConfig.Clone()
		tlsConfig.NextProtos = []string{"http/1.1"}
		dialer := websocket.Dialer{TLSClientConfig: tlsConfig, NetDialContext: f.transport.DialContext}
		ws, _, err := dialer.DialContext(t.Context(), "wss://app.example.org"+https.SshTunnelPath, nil)
		require.NoError(t, err)
		reader, writer := io.Pipe()
		go func() {
			defer writer.Close()
			for {
				kind, data, err := ws.ReadMessage()
				if err != nil || kind != websocket.BinaryMessage {
					return
				}
				if _, err := writer.Write(data); err != nil {
					return
				}
			}
		}()
		conn = &httpTunnelTestConn{Reader: reader, Writer: tunnelWSWriter{ws}, close: func() error { _ = reader.Close(); return ws.Close() }}
	case "https1":
		raw, err := net.DialTimeout("tcp", f.address, time.Second)
		require.NoError(t, err)
		tlsConfig := f.transport.TLSClientConfig.Clone()
		tlsConfig.ServerName = "app.example.org"
		tlsConfig.NextProtos = []string{"http/1.1"}
		secure := tls.Client(raw, tlsConfig)
		require.NoError(t, secure.SetDeadline(time.Now().Add(10*time.Second)))
		require.NoError(t, secure.Handshake())
		_, err = fmt.Fprintf(secure, "POST %s HTTP/1.1\r\nHost: app.example.org\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n", https.SshTunnelPath)
		require.NoError(t, err)
		res, err := http.ReadResponse(bufio.NewReader(secure), nil)
		require.NoError(t, err)
		require.Equal(t, 200, res.StatusCode)
		conn = &httpTunnelTestConn{Conn: secure, Reader: res.Body, Writer: httputil.NewChunkedWriter(secure), close: secure.Close}
	default:
		reader, writer := io.Pipe()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		context.AfterFunc(ctx, func() { _ = reader.Close() })
		req, err := http.NewRequestWithContext(ctx, "POST", "https://app.example.org"+https.SshTunnelPath, reader)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/octet-stream")
		transport := f.transport.Clone()
		transport.ForceAttemptHTTP2 = mode == "https2"
		if mode == "https1" {
			transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		t.Cleanup(transport.CloseIdleConnections)
		res, err := (&http.Client{Transport: transport}).Do(req)
		require.NoError(t, err)
		require.Equal(t, 200, res.StatusCode)
		if mode == "https2" {
			require.Equal(t, 2, res.ProtoMajor)
		} else {
			require.Equal(t, 1, res.ProtoMajor)
		}
		conn = &httpTunnelTestConn{Reader: res.Body, Writer: writer, close: func() error { cancel(); _ = writer.Close(); return res.Body.Close() }}
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func (f *sshTunnelFixture) clientConfig() *gossh.ClientConfig {
	return &gossh.ClientConfig{User: "test", Auth: []gossh.AuthMethod{gossh.Password("")}, HostKeyCallback: gossh.FixedHostKey(f.svc.tunnelServer.HostSigners[0].PublicKey())}
}

func (f *sshTunnelFixture) dial(t *testing.T, mode string) *gossh.Client {
	t.Helper()
	conn := f.transportConn(t, mode)
	cc, channels, requests, err := gossh.NewClientConn(conn, "app.example.org", f.clientConfig())
	require.NoError(t, err)
	client := gossh.NewClient(cc, channels, requests)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestSshTunnelGlobalConnectionsAreSharedAcrossTransports(t *testing.T) {
	f := newSshTunnelFixture(t, false, true, true, false, func(conf *configuration.Configuration) { conf.Ssh.MaxConnections = 2 })
	one, two := f.dial(t, "https1"), f.dial(t, "wss")
	conn := f.transportConn(t, "https2")
	_, _, _, err := gossh.NewClientConn(conn, "app.example.org", f.clientConfig())
	require.Error(t, err, "a different HTTP transport must not reset the global SSH connection limit")
	_ = conn.Close()
	// Long-lived tunnels must not consume the WebUI's small per-peer API budget.
	res := f.request(t, "POST", "/api/v1/discovery", strings.NewReader(`{"slug":"work"}`))
	require.Equal(t, 200, res.StatusCode)
	_ = one.Close()
	_ = two.Close()
}

func TestSshTunnelStartupsAreSharedAcrossTransports(t *testing.T) {
	f := newSshTunnelFixture(t, false, false, true, false, func(conf *configuration.Configuration) {
		conf.Ssh.MaxStartupsStart, conf.Ssh.MaxStartupsFull = 1, 1
		conf.Ssh.MaxStartupsRate = 100
	})
	first := f.transportConn(t, "https1")
	// Leave the first SSH handshake incomplete after its server-first banner.
	line, err := bufio.NewReader(first).ReadString('\n')
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(line, "SSH-2.0-"))
	second := f.transportConn(t, "wss")
	_, _, _, err = gossh.NewClientConn(second, "app.example.org", f.clientConfig())
	require.Error(t, err, "WSS must share the HTTP streaming handshake budget")
	_ = first.Close()
	_ = second.Close()
}

func TestSshTunnelGlobalConnectionsAreSharedWithDirectSsh(t *testing.T) {
	for _, mode := range []string{"https1", "https2", "wss"} {
		for _, directFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/direct-first=%t", mode, directFirst), func(t *testing.T) {
				f := newSshTunnelFixture(t, true, false, true, false, func(conf *configuration.Configuration) {
					conf.Ssh.MaxConnections = 1
				})
				firstMode, secondMode := mode, "direct"
				if directFirst {
					firstMode, secondMode = secondMode, firstMode
				}
				first := f.dial(t, firstMode)
				conn := f.transportConn(t, secondMode)
				_, _, _, err := gossh.NewClientConn(conn, "app.example.org", f.clientConfig())
				require.Error(t, err, "direct SSH and HTTPS must not provide separate global connection budgets")
				_ = conn.Close()
				require.NoError(t, first.Close())
				require.Eventually(t, func() bool { return f.svc.activeConnections.Load() == 0 }, time.Second, time.Millisecond)
				require.NoError(t, f.dial(t, secondMode).Close(), "closing the first connection must release its shared slot")
			})
		}
	}
}

func TestSshTunnelCannotAuthenticateThroughBrowserOnlyFlow(t *testing.T) {
	f := newSshTunnelFixture(t, false, true, true, false, func(conf *configuration.Configuration) {
		conf.Flows[0].Requirement.Ssh.ExcludedRequestingName = common.MustNewRegexp(".*")
	})
	require.Equal(t, http.StatusOK, f.request(t, "POST", "/api/v1/discovery", strings.NewReader(`{"slug":"work"}`)).StatusCode)
	for _, mode := range []string{"https1", "https2", "wss"} {
		t.Run(mode, func(t *testing.T) {
			conn := f.transportConn(t, mode)
			_, _, _, err := gossh.NewClientConn(conn, "app.example.org", f.clientConfig())
			require.Error(t, err, "a published browser flow must not authorize SSH through the tunnel")
			_ = conn.Close()
		})
	}
}

func TestSshTunnelShutdownPreservesFinalOutputAndExitStatus(t *testing.T) {
	for _, mode := range []string{"https1", "https2", "wss"} {
		t.Run(mode, func(t *testing.T) {
			env := &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
				_, err := io.WriteString(task.SshSession(), "ready\n")
				if err != nil {
					return -1, err
				}
				time.Sleep(250 * time.Millisecond)
				_, err = io.WriteString(task.SshSession(), "finished\n")
				return 23, err
			}}
			f := newSshTunnelFixture(t, false, false, true, false, func(conf *configuration.Configuration) {
				conf.Ssh.GracefulShutdownTimeout = common.DurationOf(time.Second)
				conf.Http.GracefulShutdownTimeout = common.DurationOf(time.Millisecond)
			}, env)
			client := f.dial(t, mode)
			session, err := client.NewSession()
			require.NoError(t, err)
			defer session.Close()
			reader, err := session.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, session.Start("test"))
			greeting := make([]byte, len("ready\n"))
			_, err = io.ReadFull(reader, greeting)
			require.NoError(t, err)
			require.Equal(t, "ready\n", string(greeting))
			f.cancel()
			output, err := io.ReadAll(reader)
			require.NoError(t, err)
			require.Equal(t, "finished\n", string(output))
			var exit *gossh.ExitError
			require.ErrorAs(t, session.Wait(), &exit)
			require.Equal(t, 23, exit.ExitStatus())
			require.NoError(t, f.await())
		})
	}
}

func TestSshTunnelForcedShutdownClosesHijackedAndStreamingConnections(t *testing.T) {
	for _, mode := range []string{"https1", "https2", "wss"} {
		t.Run(mode, func(t *testing.T) {
			env := &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
				if _, err := io.WriteString(task.SshSession(), "ready\n"); err != nil {
					return -1, err
				}
				<-task.Context().Done()
				return -1, nil
			}}
			f := newSshTunnelFixture(t, false, false, true, false, func(conf *configuration.Configuration) {
				conf.Ssh.GracefulShutdownTimeout = common.DurationOf(30 * time.Millisecond)
			}, env)
			client := f.dial(t, mode)
			session, err := client.NewSession()
			require.NoError(t, err)
			defer session.Close()
			reader, err := session.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, session.Start("blocked"))
			greeting := make([]byte, 6)
			_, err = io.ReadFull(reader, greeting)
			require.NoError(t, err)
			f.cancel()
			require.NoError(t, f.await())
			require.True(t, f.shutdown.forced, "the listener owner must report exhausted SSH grace")
			require.Error(t, session.Wait(), "forced closure must not report success")
			require.Zero(t, f.svc.activeConnections.Load())
			f.svc.sshTunnel.mutex.Lock()
			active := f.svc.sshTunnel.active
			f.svc.sshTunnel.mutex.Unlock()
			require.Zero(t, active)
		})
	}
}

func TestSshTunnelFrontendAdmissionIsBoundedAndReleasesPeerRecords(t *testing.T) {
	tunnel := newSshTunnel()
	var releases []func()
	for range 64 {
		release, ok := tunnel.admit("192.0.2.1")
		require.True(t, ok)
		releases = append(releases, release)
	}
	_, ok := tunnel.admit("192.0.2.1")
	require.False(t, ok)
	release, ok := tunnel.admit("192.0.2.2")
	require.True(t, ok)
	release()
	for _, release := range releases {
		release()
	}
	require.Empty(t, tunnel.peers)
	require.Zero(t, tunnel.active)
	releases = nil
	for i := range 1024 {
		release, ok := tunnel.admit(fmt.Sprintf("192.0.%d.%d", i/256, i%256))
		require.True(t, ok)
		releases = append(releases, release)
	}
	_, ok = tunnel.admit("198.51.100.1")
	require.False(t, ok, "global transport slots must also be bounded")
	for _, release := range releases {
		release()
	}
	require.Empty(t, tunnel.peers)
	require.NoError(t, tunnel.Close())
	_, ok = tunnel.admit("192.0.2.1")
	require.False(t, ok)
	tunnel.operations.waitUntilDrained()
}

func TestSshTunnelRejectsInvalidRequestsBeforeAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"plain GET", func(r *http.Request) { r.Method = "GET" }, http.StatusMethodNotAllowed},
		{"HTTP/1.0", func(r *http.Request) { r.ProtoMinor = 0 }, http.StatusMethodNotAllowed},
		{"query", func(r *http.Request) { r.URL.RawQuery = "target=elsewhere" }, http.StatusBadRequest},
		{"empty query", func(r *http.Request) { r.URL.ForceQuery = true }, http.StatusBadRequest},
		{"compression", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, http.StatusBadRequest},
		{"JSON", func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }, http.StatusBadRequest},
		{"other upgrade", func(r *http.Request) { r.Header.Set("Upgrade", "other") }, http.StatusBadRequest},
		{"invalid peer", func(r *http.Request) { r.RemoteAddr = "invalid" }, http.StatusBadRequest},
		{"WebSocket body", func(r *http.Request) {
			r.Method = "GET"
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", "websocket")
			r.ContentLength = 1
		}, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			tunnel := newSshTunnel()
			tunnel.ready.Store(true)
			defer tunnel.Close()
			r := httptest.NewRequest("POST", https.SshTunnelPath, nil)
			r.Header.Set("Content-Type", "application/octet-stream")
			test.change(r)
			w := httptest.NewRecorder()
			tunnel.ServeHTTP(w, r)
			require.Equal(t, test.status, w.Code)
			require.Zero(t, tunnel.active)
		})
	}
}

type tunnelWSWriter struct{ *websocket.Conn }

func (w tunnelWSWriter) Write(data []byte) (int, error) {
	err := w.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func TestSshTunnelRealHandshakeKeepAliveAndSharedGlobalConnections(t *testing.T) {
	for _, mode := range []string{"https1", "https2", "wss"} {
		t.Run(mode, func(t *testing.T) {
			f := newSshTunnelFixture(t, false, false, true, false, func(conf *configuration.Configuration) { conf.Ssh.ProxyProtocol = true; conf.Ssh.MaxConnections = 2 })
			client := f.dial(t, mode)
			for range 3 {
				ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				require.NoError(t, err)
				require.True(t, ok)
			}
			channel, requests, err := client.OpenChannel("session", nil)
			require.NoError(t, err)
			go gossh.DiscardRequests(requests)
			require.NoError(t, channel.Close())
			require.Eventually(t, func() bool { return f.svc.activeConnections.Load() == 1 }, time.Second, time.Millisecond)
			require.NoError(t, client.Close())
			require.Eventually(t, func() bool { return f.svc.activeConnections.Load() == 0 }, time.Second, time.Millisecond)
		})
	}
}

func TestSshTunnelBinaryStreamingAndCancellation(t *testing.T) {
	// Test the bridge itself with a payload above the ordinary API body limit.
	tunnel := newSshTunnel()
	tunnel.ready.Store(true)
	t.Cleanup(func() { _ = tunnel.Close() })
	server := &http.Server{Handler: tunnel, ReadHeaderTimeout: time.Second, ReadTimeout: time.Second}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	data := bytes.Repeat([]byte{0, 1, 10, 13, 127, 128, 255}, 300000)
	backendDone := make(chan error, 1)
	go func() {
		conn, err := tunnel.Accept()
		if err != nil {
			backendDone <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("server-first"))
		if err == nil {
			var incoming = make([]byte, len(data))
			_, err = io.ReadFull(conn, incoming)
			if err == nil && !bytes.Equal(data, incoming) {
				err = fmt.Errorf("corrupted binary stream")
			}
			if err == nil {
				_, err = conn.Write(incoming)
			}
		}
		backendDone <- err
	}()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n", https.SshTunnelPath)
	require.NoError(t, err)
	writer := httputil.NewChunkedWriter(conn)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode)
	defer response.Body.Close()
	greeting := make([]byte, len("server-first"))
	_, err = io.ReadFull(response.Body, greeting)
	require.NoError(t, err)
	require.Equal(t, "server-first", string(greeting))
	_, err = writer.Write(data)
	require.NoError(t, err)
	result, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, data, result)
	require.NoError(t, <-backendDone)
	_ = writer.Close()
	require.Eventually(t, func() bool { tunnel.mutex.Lock(); defer tunnel.mutex.Unlock(); return tunnel.active == 0 }, time.Second, time.Millisecond)
}
