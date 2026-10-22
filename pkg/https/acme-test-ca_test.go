package https

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

type acmeTestClock struct{ value atomic.Int64 }

func newACMETestClock() *acmeTestClock {
	clock := &acmeTestClock{}
	clock.value.Store(time.Now().Truncate(time.Second).UnixNano())
	return clock
}
func (this *acmeTestClock) now() time.Time                 { return time.Unix(0, this.value.Load()) }
func (this *acmeTestClock) advance(duration time.Duration) { this.value.Add(int64(duration)) }

type acmeTestOrder struct {
	domain, status, token string
	certificate           []byte
}

type acmeTestCounts struct{ requests, registrations, issues, proofs int }

func (this *acmeTestCA) counts() acmeTestCounts {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return acmeTestCounts{this.requests, this.registrations, this.issues, this.proofs}
}

type acmeTestCA struct {
	server                                  *httptest.Server
	clock                                   *acmeTestClock
	root                                    *x509.Certificate
	rootDER                                 []byte
	key                                     *ecdsa.PrivateKey
	mutex                                   sync.Mutex
	nonces                                  map[string]bool
	accounts                                map[string]*ecdsa.PublicKey
	orders                                  map[int]*acmeTestOrder
	requests, registrations, issues, proofs int
	failOrders                              bool
	failDomain                              string
	wrongIdentifier                         bool
	wrongIssuedDomain                       bool
	staleIssuedCertificate                  bool
	httpOnly                                bool
	hangOrders                              bool
	orderStarted                            chan struct{}
	hangChallenge                           bool
	challengeStarted                        chan struct{}
	probe                                   func(string, string, *ecdsa.PublicKey) error
}

func newACMETestCA(t *testing.T, clock *acmeTestClock) *acmeTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local ACME test CA"}, NotBefore: clock.now().Add(-24 * time.Hour), NotAfter: clock.now().Add(4 * 365 * 24 * time.Hour), KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	require.NoError(t, err)
	root, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	ca := &acmeTestCA{clock: clock, root: root, rootDER: der, key: key, nonces: make(map[string]bool), accounts: make(map[string]*ecdsa.PublicKey), orders: make(map[int]*acmeTestOrder)}
	ca.server = httptest.NewTLSServer(http.HandlerFunc(ca.serveHTTP))
	t.Cleanup(ca.server.Close)
	return ca
}

func (this *acmeTestCA) serveHTTP(response http.ResponseWriter, request *http.Request) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.requests++
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	freshNonce := base64.RawURLEncoding.EncodeToString(nonce[:])
	this.nonces[freshNonce] = true
	response.Header().Set("Replay-Nonce", freshNonce)
	response.Header().Set("Content-Type", "application/json")
	url := this.server.URL
	if request.URL.Path == "/directory" {
		_ = json.NewEncoder(response).Encode(map[string]any{"newNonce": url + "/nonce", "newAccount": url + "/account", "newOrder": url + "/new-order", "meta": map[string]string{"termsOfService": url + "/terms"}})
		return
	}
	if request.URL.Path == "/nonce" {
		response.WriteHeader(http.StatusNoContent)
		return
	}
	key, payload, err := this.verifyJWS(request)
	if err != nil {
		this.problem(response, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	if request.URL.Path == "/account" {
		var account struct {
			Terms bool `json:"termsOfServiceAgreed"`
		}
		if err := json.Unmarshal(payload, &account); err != nil || !account.Terms {
			this.problem(response, 400, "malformed", "explicit terms agreement missing")
			return
		}
		kid := url + "/account/" + testJWKThumbprint(key)
		status := http.StatusCreated
		if this.accounts[kid] != nil {
			status = http.StatusOK
		} else {
			this.registrations++
		}
		this.accounts[kid] = key
		response.Header().Set("Location", kid)
		response.WriteHeader(status)
		_ = json.NewEncoder(response).Encode(map[string]string{"status": "valid", "orders": url + "/orders"})
		return
	}
	if request.URL.Path == "/new-order" {
		if this.orderStarted != nil {
			select {
			case this.orderStarted <- struct{}{}:
			default:
			}
		}
		if this.hangOrders {
			<-request.Context().Done()
			return
		}
		if this.failOrders {
			response.Header().Set("Retry-After", "7200")
			this.problem(response, 429, "rateLimited", "local test limit")
			return
		}
		var order struct {
			Identifiers []struct{ Type, Value string }
		}
		if err := json.Unmarshal(payload, &order); err != nil || len(order.Identifiers) != 1 || order.Identifiers[0].Type != "dns" {
			this.problem(response, 400, "malformed", "expected one DNS identifier")
			return
		}
		if order.Identifiers[0].Value == this.failDomain {
			this.problem(response, 503, "serverInternal", "local domain failure")
			return
		}
		id := len(this.orders) + 1
		this.orders[id] = &acmeTestOrder{domain: order.Identifiers[0].Value, status: "pending", token: fmt.Sprintf("test-token-%d", id)}
		response.Header().Set("Location", fmt.Sprintf("%s/order/%d", url, id))
		response.WriteHeader(http.StatusCreated)
		this.writeOrder(response, id)
		return
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) != 2 {
		this.problem(response, 404, "malformed", "unknown endpoint")
		return
	}
	id, err := strconv.Atoi(parts[1])
	if err != nil || this.orders[id] == nil {
		this.problem(response, 404, "malformed", "unknown order")
		return
	}
	order := this.orders[id]
	switch parts[0] {
	case "auth":
		status := "pending"
		if order.status != "pending" {
			status = "valid"
		}
		typeName := "tls-alpn-01"
		if this.httpOnly {
			typeName = "http-01"
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": order.domain}, "challenges": []map[string]string{{"type": typeName, "status": status, "token": order.token, "url": fmt.Sprintf("%s/challenge/%d", url, id)}}})
	case "challenge":
		if this.challengeStarted != nil {
			select {
			case this.challengeStarted <- struct{}{}:
			default:
			}
		}
		if this.hangChallenge {
			<-request.Context().Done()
			return
		}
		if this.probe == nil {
			this.problem(response, 400, "unauthorized", "TLS probe is not configured")
			return
		}
		if err := this.probe(order.domain, order.token, key); err != nil {
			this.problem(response, 400, "unauthorized", err.Error())
			return
		}
		this.proofs++
		order.status = "ready"
		_ = json.NewEncoder(response).Encode(map[string]string{"type": "tls-alpn-01", "status": "valid", "token": order.token, "url": fmt.Sprintf("%s/challenge/%d", url, id)})
	case "order":
		this.writeOrder(response, id)
	case "finalize":
		if order.status != "ready" {
			this.problem(response, 400, "orderNotReady", "order is not authorized")
			return
		}
		var value struct{ CSR string }
		if err := json.Unmarshal(payload, &value); err != nil {
			this.problem(response, 400, "malformed", "invalid CSR payload")
			return
		}
		encoded, err := base64.RawURLEncoding.DecodeString(value.CSR)
		if err != nil {
			this.problem(response, 400, "badCSR", "invalid CSR encoding")
			return
		}
		csr, err := x509.ParseCertificateRequest(encoded)
		if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 1 || csr.DNSNames[0] != order.domain || len(csr.IPAddresses) != 0 {
			this.problem(response, 400, "badCSR", "invalid CSR signature or identifiers")
			return
		}
		this.issues++
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(this.issues + 10)), DNSNames: []string{order.domain}, NotBefore: this.clock.now().Add(-time.Hour), NotAfter: this.clock.now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
		if this.wrongIssuedDomain {
			leaf.DNSNames = []string{"wrong.example.org"}
		}
		if this.staleIssuedCertificate {
			leaf.NotBefore = this.clock.now().Add(-89 * 24 * time.Hour)
			leaf.NotAfter = this.clock.now().Add(24 * time.Hour)
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, this.root, csr.PublicKey, this.key)
		if err != nil {
			this.problem(response, 500, "serverInternal", "cannot sign certificate")
			return
		}
		order.certificate = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: this.rootDER})...)
		order.status = "valid"
		this.writeOrder(response, id)
	case "certificate":
		response.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = response.Write(order.certificate)
	default:
		this.problem(response, 404, "malformed", "unknown endpoint")
	}
}

func (this *acmeTestCA) writeOrder(response http.ResponseWriter, id int) {
	order := this.orders[id]
	domain := order.domain
	if this.wrongIdentifier {
		domain = "unconfigured.example.org"
	}
	_ = json.NewEncoder(response).Encode(map[string]any{"status": order.status, "identifiers": []map[string]string{{"type": "dns", "value": domain}}, "authorizations": []string{fmt.Sprintf("%s/auth/%d", this.server.URL, id)}, "finalize": fmt.Sprintf("%s/finalize/%d", this.server.URL, id), "certificate": fmt.Sprintf("%s/certificate/%d", this.server.URL, id)})
}
func (*acmeTestCA) problem(response http.ResponseWriter, status int, kind, detail string) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{"status": status, "type": "urn:ietf:params:acme:error:" + kind, "detail": detail})
}

func (this *acmeTestCA) verifyJWS(request *http.Request) (*ecdsa.PublicKey, []byte, error) {
	var envelope struct{ Protected, Payload, Signature string }
	if err := json.NewDecoder(io.LimitReader(request.Body, maximumACMEStateBytes)).Decode(&envelope); err != nil {
		return nil, nil, err
	}
	protected, err := base64.RawURLEncoding.DecodeString(envelope.Protected)
	if err != nil {
		return nil, nil, err
	}
	var header struct {
		Alg, Kid, Nonce, URL string
		JWK                  *struct{ Kty, Crv, X, Y string }
	}
	if err := json.Unmarshal(protected, &header); err != nil {
		return nil, nil, err
	}
	if header.Alg != "ES256" || header.URL != this.server.URL+request.URL.Path || !this.nonces[header.Nonce] {
		return nil, nil, fmt.Errorf("invalid JWS algorithm, URL or nonce")
	}
	delete(this.nonces, header.Nonce)
	key := this.accounts[header.Kid]
	if header.JWK != nil {
		if header.JWK.Kty != "EC" || header.JWK.Crv != "P-256" {
			return nil, nil, fmt.Errorf("invalid account JWK")
		}
		x, err := base64.RawURLEncoding.DecodeString(header.JWK.X)
		if err != nil {
			return nil, nil, err
		}
		y, err := base64.RawURLEncoding.DecodeString(header.JWK.Y)
		if err != nil {
			return nil, nil, err
		}
		key = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	}
	if key == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, nil, fmt.Errorf("unregistered account key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != 64 {
		return nil, nil, fmt.Errorf("invalid JWS signature length")
	}
	digest := sha256.Sum256([]byte(envelope.Protected + "." + envelope.Payload))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return nil, nil, fmt.Errorf("invalid JWS signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	return key, payload, err
}

func testJWKThumbprint(key *ecdsa.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))
	digest := sha256.Sum256([]byte(fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, x, y)))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func startACMETestTLS(t *testing.T, manager *TLS) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var connections sync.WaitGroup
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer connection.Close()
				handshake, stop := context.WithTimeout(ctx, 5*time.Second)
				defer stop()
				_ = tls.Server(connection, manager.Config()).HandshakeContext(handshake)
			}()
		}
	}()
	t.Cleanup(func() { cancel(); _ = listener.Close(); <-done; connections.Wait() })
	return listener.Addr().String()
}

func (this *acmeTestCA) setProbe(address string) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.probe = func(domain, token string, accountKey *ecdsa.PublicKey) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		client := &tls.Dialer{Config: &tls.Config{ServerName: domain, NextProtos: []string{acme.ALPNProto}, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}} //nolint:gosec // RFC 8737 uses a self-signed proof, verified explicitly below.
		connection, err := client.DialContext(ctx, "tcp", address)
		if err != nil {
			return err
		}
		defer connection.Close()
		state := connection.(*tls.Conn).ConnectionState()
		if state.NegotiatedProtocol != acme.ALPNProto || len(state.PeerCertificates) != 1 {
			return fmt.Errorf("not a TLS-ALPN-01 proof")
		}
		leaf := state.PeerCertificates[0]
		if !validAt(leaf, this.clock.now()) || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != domain || leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
			return fmt.Errorf("invalid proof certificate")
		}
		expected := sha256.Sum256([]byte(token + "." + testJWKThumbprint(accountKey)))
		for _, extension := range leaf.Extensions {
			if !extension.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}) {
				continue
			}
			var digest []byte
			rest, err := asn1.Unmarshal(extension.Value, &digest)
			if err == nil && len(rest) == 0 && extension.Critical && string(digest) == string(expected[:]) {
				return nil
			}
		}
		return fmt.Errorf("proof is not bound to the expected token and account JWK")
	}
}
