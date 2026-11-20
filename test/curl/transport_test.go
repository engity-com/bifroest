//go:build e2e

package curl_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const (
	probeTimeout    = 12 * time.Second
	exchangeTimeout = 3 * time.Second
	maximumOutput   = 8 << 20
	wsProtocol      = "bifroest-curl-probe.v1"
)

type transport struct {
	name, scheme string
	protocol     int
	websocket    bool
	emptyClose   bool
}

var transports = []transport{
	{name: "http1", scheme: "http", protocol: 1},
	{name: "https1", scheme: "https", protocol: 1},
	{name: "https2", scheme: "https", protocol: 2},
	{name: "ws", scheme: "ws", protocol: 1, websocket: true},
	{name: "wss", scheme: "wss", protocol: 1, websocket: true},
	{name: "ws-empty-close", scheme: "ws", protocol: 1, websocket: true, emptyClose: true},
	{name: "wss-empty-close", scheme: "wss", protocol: 1, websocket: true, emptyClose: true},
}

// Cover every byte, including NUL, CR/LF and IAC, then use nonrepeating blocks
// to expose lost/reordered chunks across pipe, HTTP and WebSocket buffers.
var roundSizes = []int{1, 1027, 128*1024 + 37, 3*1024*1024 + 37}

func payload(size, salt int) []byte {
	result := make([]byte, size)
	random := mathrand.New(mathrand.NewPCG(uint64(salt), 42))
	for i := range result {
		if i < 256 {
			result[i] = byte(i*73 + salt)
		} else {
			result[i] = byte(random.Uint64())
		}
	}
	return result
}

func greeting() []byte {
	return append([]byte("SSH-2.0-bifroest-curl-probe\r\n"), payload(256, 0)...)
}

func trailer() []byte { return payload(513, 91) }

type certificates struct {
	server tls.Certificate
	roots  *x509.CertPool
	file   string
}

func newCertificates(t *testing.T) certificates {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Bifroest curl test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	// Schannel checks revocation even with an explicit --cacert. Supply a real
	// local CRL instead of disabling certificate or revocation verification.
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
	}, root, key)
	if err != nil {
		t.Fatal(err)
	}
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crl)
	}))
	t.Cleanup(crlServer.Close)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CRLDistributionPoints: []string{crlServer.URL + "/ca.crl"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return certificates{server: tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}, roots: roots, file: file}
}

type endpoint struct {
	url    string
	server *httptest.Server
	result chan error
	pong   chan struct{}
}

type serverOptions struct {
	bufferResponse  bool
	corruptReply    bool
	concurrentReply bool
}

func newEndpoint(t *testing.T, mode transport, cert certificates, options serverOptions) *endpoint {
	t.Helper()
	e := &endpoint{result: make(chan error, 1), pong: make(chan struct{}, 1)}
	e.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		defer func() { e.result <- err }()
		if r.URL.Path != "/stream" || r.ProtoMajor != mode.protocol {
			err = fmt.Errorf("unexpected request: %s %s %s", r.Method, r.URL.Path, r.Proto)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if mode.websocket {
			err = e.serveWebSocket(w, r, options, mode.emptyClose)
		} else {
			err = serveHTTP(w, r, options)
		}
	}))
	e.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	e.server.Config.ReadHeaderTimeout = exchangeTimeout
	if mode.scheme == "https" || mode.scheme == "wss" {
		e.server.TLS = &tls.Config{Certificates: []tls.Certificate{cert.server}, MinVersion: tls.VersionTLS12}
		e.server.EnableHTTP2 = mode.protocol == 2
		e.server.StartTLS()
	} else {
		e.server.Start()
	}
	e.url = mode.scheme + strings.TrimPrefix(strings.TrimPrefix(e.server.URL, "https"), "http") + "/stream"
	t.Cleanup(e.server.Close)
	return e
}

func serveHTTP(w http.ResponseWriter, r *http.Request, options serverOptions) error {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/octet-stream" {
		http.Error(w, "binary POST required", http.StatusBadRequest)
		return fmt.Errorf("expected binary POST, got %s %q", r.Method, r.Header.Get("Content-Type"))
	}
	controller := http.NewResponseController(w)
	if r.ProtoMajor == 1 {
		if err := controller.EnableFullDuplex(); err != nil {
			return err
		}
	}
	if err := controller.SetReadDeadline(time.Now().Add(probeTimeout)); err != nil {
		return err
	}
	if err := controller.SetWriteDeadline(time.Now().Add(probeTimeout)); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	write := func(data []byte) error {
		if _, err := w.Write(data); err != nil {
			return err
		}
		if options.bufferResponse {
			return nil
		}
		return controller.Flush()
	}
	if err := exchange(r.Body, write, options); err != nil {
		return err
	}
	// The response remains readable after upload EOF: no whole-request buffering.
	var extra [1]byte
	if n, err := r.Body.Read(extra[:]); n != 0 || err != io.EOF {
		return fmt.Errorf("expected upload EOF, got %d bytes and %v", n, err)
	}
	return write(trailer())
}

func exchange(read io.Reader, write func([]byte) error, options serverOptions) error {
	if err := write(greeting()); err != nil {
		return fmt.Errorf("server-first greeting: %w", err)
	}
	for round, size := range roundSizes {
		reply := payload(size+257, round+101)
		if options.corruptReply {
			reply[len(reply)-1] ^= 0xff
		}
		var writing chan error
		if options.concurrentReply {
			writing = make(chan error, 1)
			go func() { writing <- write(reply) }()
		}
		data := make([]byte, size)
		_, readErr := io.ReadFull(read, data)
		var writeErr error
		if writing != nil {
			writeErr = <-writing
		} else {
			writeErr = write(reply)
		}
		if readErr != nil {
			return fmt.Errorf("round %d input: %w", round, readErr)
		}
		if !bytes.Equal(data, payload(size, round+1)) {
			return fmt.Errorf("round %d input corrupted", round)
		}
		if err := writeErr; err != nil {
			return fmt.Errorf("round %d output: %w", round, err)
		}
	}
	return nil
}

func (e *endpoint) serveWebSocket(w http.ResponseWriter, r *http.Request, options serverOptions, emptyClose bool) error {
	if r.Method != http.MethodGet {
		http.Error(w, "WebSocket GET required", http.StatusBadRequest)
		return fmt.Errorf("expected WebSocket GET, got %s", r.Method)
	}
	upgrader := websocket.Upgrader{Subprotocols: []string{wsProtocol}}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	if conn.Subprotocol() != wsProtocol {
		return fmt.Errorf("missing WebSocket subprotocol")
	}
	conn.SetReadLimit(maximumOutput)
	if err := conn.SetReadDeadline(time.Now().Add(probeTimeout)); err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(probeTimeout)); err != nil {
		return err
	}
	conn.SetPongHandler(func(value string) error {
		if value != "idle-stdin" {
			return fmt.Errorf("unexpected pong %q", value)
		}
		select {
		case e.pong <- struct{}{}:
		default:
		}
		return nil
	})
	write := func(data []byte) error { return conn.WriteMessage(websocket.BinaryMessage, data) }
	first := true
	err = exchange(&binaryReader{conn: conn}, func(data []byte) error {
		if err := write(data); err != nil {
			return err
		}
		if first {
			first = false
			return conn.WriteControl(websocket.PingMessage, []byte("idle-stdin"), time.Now().Add(exchangeTimeout))
		}
		return nil
	}, options)
	if err != nil {
		return err
	}
	if err := write(trailer()); err != nil {
		return err
	}
	closePayload := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	if emptyClose {
		// An empty CLOSE is valid too. Probe it separately; never strip control
		// payloads from stdout to make a corrupted byte stream appear suitable.
		closePayload = nil
	}
	return conn.WriteControl(websocket.CloseMessage, closePayload, time.Now().Add(exchangeTimeout))
}

// SSH is a byte stream; WebSocket message boundaries must not change it, and
// text frames are not a substitute for a binary-safe transport.
type binaryReader struct {
	conn    *websocket.Conn
	current io.Reader
}

func (r *binaryReader) Read(data []byte) (int, error) {
	for {
		if r.current == nil {
			kind, next, err := r.conn.NextReader()
			if err != nil {
				return 0, err
			}
			if kind != websocket.BinaryMessage {
				return 0, fmt.Errorf("expected binary WebSocket frame, got %d", kind)
			}
			r.current = next
		}
		n, err := r.current.Read(data)
		if err == io.EOF {
			r.current = nil
			if n == 0 {
				continue
			}
			err = nil
		}
		return n, err
	}
}
