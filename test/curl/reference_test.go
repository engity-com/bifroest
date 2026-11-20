//go:build e2e

package curl_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Independent clients prove that a curl failure is not a broken test server.
func TestReferenceTransports(t *testing.T) {
	cert := newCertificates(t)
	for _, mode := range transports {
		t.Run(mode.name, func(t *testing.T) {
			e := newEndpoint(t, mode, cert, serverOptions{})
			ctx, cancel := context.WithTimeout(t.Context(), probeTimeout)
			defer cancel()
			p := startReference(ctx, mode, e.url, cert)
			defer p.stop()
			if err := exercise(ctx, p, e, mode.websocket); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReferenceConcurrentWebSocketDuplex(t *testing.T) {
	cert := newCertificates(t)
	mode := transports[6]
	e := newEndpoint(t, mode, cert, serverOptions{concurrentReply: true})
	ctx, cancel := context.WithTimeout(t.Context(), probeTimeout)
	defer cancel()
	p := startReference(ctx, mode, e.url, cert)
	defer p.stop()
	if err := exercise(ctx, p, e, true); err != nil {
		t.Fatal(err)
	}
}

func TestProbeRejectsUnsuitableStreams(t *testing.T) {
	cert := newCertificates(t)
	for _, test := range []struct {
		name    string
		options serverOptions
		want    string
	}{
		{name: "buffered response", options: serverOptions{bufferResponse: true}, want: "server-first output"},
		{name: "corrupted binary", options: serverOptions{corruptReply: true}, want: "stdout bytes differ"},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := newEndpoint(t, transports[0], cert, test.options)
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			p := startReference(ctx, transports[0], e.url, cert)
			defer p.stop()
			err := exercise(ctx, p, e, false)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q rejection, got %v", test.want, err)
			}
		})
	}
}

func TestRequiredTransports(t *testing.T) {
	for _, test := range []struct {
		value string
		want  []string
	}{
		{value: "", want: []string{"http1", "https1"}},
		{value: "all", want: []string{"http1", "https1", "https2", "ws", "wss", "ws-empty-close", "wss-empty-close"}},
		{value: "none"},
		{value: "http1, wss", want: []string{"http1", "wss"}},
	} {
		actual, err := requiredTransports(test.value)
		if err != nil {
			t.Errorf("%q: %v", test.value, err)
			continue
		}
		if len(actual) != len(test.want) {
			t.Errorf("%q: got %v, want %v", test.value, actual, test.want)
		}
		for _, name := range test.want {
			if !actual[name] {
				t.Errorf("%q: missing required transport %q", test.value, name)
			}
		}
	}
	for _, value := range []string{"typo", "http1,", "none,wss"} {
		if _, err := requiredTransports(value); err == nil {
			t.Errorf("%q: expected an error", value)
		}
	}
}

func startReference(parent context.Context, mode transport, url string, cert certificates) *runningPeer {
	ctx, cancel := context.WithCancel(parent)
	input, writer := io.Pipe()
	p := &runningPeer{input: writer, stdout: newCapture(), stderr: newCapture(), done: make(chan struct{}), cancel: cancel}
	go func() {
		defer close(p.done)
		defer input.Close()
		if mode.websocket {
			p.result = referenceWebSocket(ctx, url, cert, input, p.stdout)
			return
		}
		transport := &http.Transport{ForceAttemptHTTP2: mode.protocol == 2, TLSClientConfig: &tls.Config{RootCAs: cert.roots, MinVersion: tls.VersionTLS12}}
		defer transport.CloseIdleConnections()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, input)
		if err != nil {
			p.result = err
			return
		}
		request.Header.Set("Content-Type", "application/octet-stream")
		response, err := (&http.Client{Transport: transport}).Do(request)
		if err != nil {
			p.result = err
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			p.result = fmt.Errorf("reference response: %s", response.Status)
			return
		}
		_, p.result = io.Copy(p.stdout, response.Body)
	}()
	return p
}

func referenceWebSocket(ctx context.Context, url string, cert certificates, input io.ReadCloser, output io.Writer) error {
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: cert.roots, MinVersion: tls.VersionTLS12}, Subprotocols: []string{wsProtocol}}
	conn, response, err := dialer.DialContext(ctx, url, nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	var writes sync.WaitGroup
	writes.Add(1)
	defer func() {
		_ = input.Close()
		_ = conn.Close()
		writes.Wait()
	}()
	go func() {
		defer writes.Done()
		data := make([]byte, 16384)
		for {
			n, err := input.Read(data)
			if n > 0 {
				if writeErr := conn.WriteMessage(websocket.BinaryMessage, data[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		kind, data, err := conn.ReadMessage()
		if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseNoStatusReceived) {
			return nil
		}
		if err != nil {
			return err
		}
		if kind != websocket.BinaryMessage {
			return fmt.Errorf("reference expected binary message")
		}
		if _, err := output.Write(data); err != nil {
			return err
		}
	}
}
