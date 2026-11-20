//go:build e2e

package curl_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type curlInstallation struct {
	path, version string
	windows       bool
}

func installations(t *testing.T) []curlInstallation {
	t.Helper()
	names := []string{"curl"}
	explicit := os.Getenv("BIFROEST_TEST_CURL")
	if explicit != "" {
		names = []string{explicit}
	} else if runtime.GOOS == "linux" && os.Getenv("WSL_INTEROP") != "" {
		names = append(names, "curl.exe")
	}
	var result []curlInstallation
	seen := make(map[string]bool)
	for _, name := range names {
		path, err := exec.LookPath(name)
		if err != nil {
			if explicit != "" {
				t.Fatal(err)
			}
			continue
		}
		path, err = filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		ctx, cancel := context.WithTimeout(t.Context(), exchangeTimeout)
		output, err := exec.CommandContext(ctx, path, "--disable", "--version").CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("%s --version: %v\n%s", path, err, output)
		}
		result = append(result, curlInstallation{path: path, version: strings.TrimSpace(string(output)), windows: strings.HasSuffix(strings.ToLower(path), ".exe")})
	}
	if len(result) == 0 {
		t.Fatal("no curl installation found; install curl or set BIFROEST_TEST_CURL")
	}
	return result
}

func requiredTransports(value string) (map[string]bool, error) {
	if value == "" {
		value = "http1,https1"
	}
	result := make(map[string]bool)
	if value == "none" {
		return result, nil
	}
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		found := false
		for _, mode := range transports {
			if name == "all" || name == mode.name {
				result[mode.name] = true
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown required transport %q (see test/curl/README.md for profiles)", name)
		}
	}
	return result, nil
}

func curlArguments(mode transport, url, ca string) []string {
	// Bound the process externally: --max-time makes some curl versions wait
	// for stdin inside the nonblocking read callback, preventing full duplex.
	args := []string{
		"--disable", "--silent", "--show-error", "--no-progress-meter", "--fail", "--no-buffer",
		"--proxy", "", "--noproxy", "*", "--connect-timeout", "3",
		"--upload-file", ".", "--header", "Expect:",
	}
	if mode.protocol == 2 {
		args = append(args, "--http2-prior-knowledge")
	} else {
		args = append(args, "--http1.1")
	}
	if mode.websocket {
		args = append(args, "--request", "GET", "--header", "Sec-WebSocket-Protocol: "+wsProtocol)
	} else {
		args = append(args, "--request", "POST", "--header", "Content-Type: application/octet-stream")
	}
	if mode.scheme == "https" || mode.scheme == "wss" {
		args = append(args, "--cacert", ca)
	}
	return append(args, "--url", url)
}

func (c curlInstallation) caPath(t *testing.T, path string) string {
	t.Helper()
	if !c.windows || runtime.GOOS == "windows" {
		return path
	}
	ctx, cancel := context.WithTimeout(t.Context(), exchangeTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "wslpath", "-w", path).CombinedOutput()
	if err != nil {
		t.Fatalf("convert CA path for native Windows curl: %v\n%s", err, output)
	}
	return strings.TrimSpace(string(output))
}

func TestCurlTransportCapabilities(t *testing.T) {
	required, err := requiredTransports(os.Getenv("BIFROEST_TEST_CURL_REQUIRE"))
	if err != nil {
		t.Fatal(err)
	}
	cert := newCertificates(t)
	for _, installation := range installations(t) {
		t.Run(filepath.Base(installation.path), func(t *testing.T) {
			t.Logf("executable: %s\n%s", installation.path, installation.version)
			ca := installation.caPath(t, cert.file)
			for _, mode := range transports {
				t.Run(mode.name, func(t *testing.T) {
					endpoint := newEndpoint(t, mode, cert, serverOptions{})
					ctx, cancel := context.WithTimeout(t.Context(), probeTimeout)
					defer cancel()
					args := curlArguments(mode, endpoint.url, ca)
					peer, err := startCurl(ctx, installation.path, args)
					if err != nil {
						t.Fatal(err)
					}
					defer peer.stop()
					err = exercise(ctx, peer, endpoint, mode.websocket)
					if err != nil {
						message := fmt.Sprintf("UNSUITABLE %s: %v\narguments: %q", mode.name, err, args)
						select {
						case <-peer.done:
							if peer.result != nil {
								message += fmt.Sprintf("\nstderr: %s", peer.stderr.snapshot())
							}
						default:
							message += fmt.Sprintf("\nstderr: %s", peer.stderr.snapshot())
						}
						if required[mode.name] {
							t.Fatal(message)
						}
						t.Skip(message)
					}
					t.Logf("SUITABLE %s: server-first output, alternating binary exchanges with open stdin, large payload and clean exit", mode.name)
				})
			}
		})
	}
}

func TestCurlConcurrentWebSocketDuplex(t *testing.T) {
	required, err := requiredTransports(os.Getenv("BIFROEST_TEST_CURL_REQUIRE"))
	if err != nil {
		t.Fatal(err)
	}
	cert := newCertificates(t)
	mode := transports[6] // WSS with byte-clean empty close.
	for _, installation := range installations(t) {
		t.Run(filepath.Base(installation.path), func(t *testing.T) {
			endpoint := newEndpoint(t, mode, cert, serverOptions{concurrentReply: true})
			ctx, cancel := context.WithTimeout(t.Context(), probeTimeout)
			defer cancel()
			peer, err := startCurl(ctx, installation.path, curlArguments(mode, endpoint.url, installation.caPath(t, cert.file)))
			if err != nil {
				t.Fatal(err)
			}
			defer peer.stop()
			if err := exercise(ctx, peer, endpoint, true); err != nil {
				message := fmt.Sprintf("UNSUITABLE concurrent WSS duplex: %v\nstderr: %s", err, peer.stderr.snapshot())
				if required[mode.name] {
					t.Fatal(message)
				}
				t.Skip(message)
			}
		})
	}
}

func TestCurlRejectsUntrustedCA(t *testing.T) {
	cert, unrelated := newCertificates(t), newCertificates(t)
	for _, installation := range installations(t) {
		t.Run(filepath.Base(installation.path), func(t *testing.T) {
			e := newEndpoint(t, transports[1], cert, serverOptions{})
			ctx, cancel := context.WithTimeout(t.Context(), probeTimeout)
			defer cancel()
			args := curlArguments(transports[1], e.url, installation.caPath(t, unrelated.file))
			peer, err := startCurl(ctx, installation.path, args)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.stop()
			_ = peer.input.Close()
			select {
			case <-peer.done:
				var exit *exec.ExitError
				if !errors.As(peer.result, &exit) || exit.ExitCode() != 60 {
					t.Fatalf("expected certificate rejection (curl exit 60), got %v\n%s", peer.result, peer.stderr.snapshot())
				}
			case <-ctx.Done():
				t.Fatal("curl did not reject the untrusted CA in time")
			}
		})
	}
}

type capture struct {
	mutex   sync.Mutex
	data    []byte
	changed chan struct{}
}

func newCapture() *capture { return &capture{changed: make(chan struct{}, 1)} }

func (c *capture) Write(data []byte) (int, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if len(c.data)+len(data) > maximumOutput {
		return 0, fmt.Errorf("probe output exceeds %d bytes", maximumOutput)
	}
	c.data = append(c.data, data...)
	select {
	case c.changed <- struct{}{}:
	default:
	}
	return len(data), nil
}

func (c *capture) snapshot() []byte {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return bytes.Clone(c.data)
}

type runningPeer struct {
	input          io.WriteCloser
	stdout, stderr *capture
	done           chan struct{}
	result         error // Published by closing done.
	cancel         context.CancelFunc
}

func startCurl(parent context.Context, path string, args []string) (*runningPeer, error) {
	ctx, cancel := context.WithCancel(parent)
	p := &runningPeer{stdout: newCapture(), stderr: newCapture(), done: make(chan struct{}), cancel: cancel}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = time.Second
	// The probe must not write TLS key logs requested by the surrounding shell.
	cmd.Env = slices.DeleteFunc(os.Environ(), func(value string) bool {
		name, _, _ := strings.Cut(value, "=")
		return strings.EqualFold(name, "SSLKEYLOGFILE")
	})
	cmd.Stdout, cmd.Stderr = p.stdout, p.stderr
	var err error
	p.input, err = cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = p.input.Close()
		cancel()
		return nil, err
	}
	go func() { p.result = cmd.Wait(); close(p.done) }()
	return p, nil
}

func (p *runningPeer) stop() {
	p.cancel()
	_ = p.input.Close()
	<-p.done
}

func (p *runningPeer) expect(ctx context.Context, expected []byte, phase string) error {
	ctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()
	for {
		actual := p.stdout.snapshot()
		if len(actual) >= len(expected) {
			if !bytes.Equal(actual[:len(expected)], expected) {
				return fmt.Errorf("%s: stdout bytes differ (received %d, expected prefix %d)", phase, len(actual), len(expected))
			}
			return nil
		}
		select {
		case <-p.stdout.changed:
		case <-p.done:
			// Stdout copying completes before done closes; inspect it once more.
			if len(p.stdout.snapshot()) >= len(expected) {
				continue
			}
			return fmt.Errorf("%s: process ended before output (%v)", phase, p.result)
		case <-ctx.Done():
			return fmt.Errorf("%s: %w (received %d/%d bytes)", phase, ctx.Err(), len(actual), len(expected))
		}
	}
}

func exercise(ctx context.Context, p *runningPeer, e *endpoint, websocket bool) error {
	expected := greeting()
	if err := p.expect(ctx, expected, "server-first output while stdin is idle"); err != nil {
		return err
	}
	if websocket {
		select {
		case <-e.pong:
		case <-p.done:
			return fmt.Errorf("WebSocket closed before idle-stdin pong: %v", p.result)
		case <-time.After(exchangeTimeout):
			return fmt.Errorf("no WebSocket pong while stdin is idle")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for round, size := range roundSizes {
		data := payload(size, round+1)
		if n, err := p.input.Write(data); err != nil || n != len(data) {
			return fmt.Errorf("round %d stdin: wrote %d/%d bytes (%v)", round, n, len(data), err)
		}
		expected = append(expected, payload(size+257, round+101)...)
		if err := p.expect(ctx, expected, fmt.Sprintf("round %d response before stdin EOF", round)); err != nil {
			return err
		}
	}
	if err := p.input.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return fmt.Errorf("close stdin: %w", err)
	}
	expected = append(expected, trailer()...)
	if err := p.expect(ctx, expected, "final response"); err != nil {
		return err
	}
	select {
	case <-p.done:
		if p.result != nil {
			return fmt.Errorf("process exit: %w", p.result)
		}
	case <-ctx.Done():
		return fmt.Errorf("process did not exit: %w", ctx.Err())
	}
	if actual := p.stdout.snapshot(); !bytes.Equal(actual, expected) {
		extra := actual[len(expected):]
		return fmt.Errorf("unexpected extra stdout bytes: %d bytes, first bytes %x", len(extra), extra[:min(len(extra), 32)])
	}
	select {
	case err := <-e.result:
		return err
	case <-ctx.Done():
		return fmt.Errorf("server did not finish: %w", ctx.Err())
	}
}
