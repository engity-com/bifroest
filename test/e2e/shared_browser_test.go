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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/recording"
)

const sharedBrowserMarker = "/home/e2e/bifroest-web-marker"

func requireSharedWorkloadBrowser(t *testing.T) string {
	t.Helper()
	if os.Getenv("BIFROEST_TEST_BROWSER_UI") != "1" {
		t.Skip("set BIFROEST_TEST_BROWSER_UI=1 after frontend build and Chromium installation")
	}
	if node := os.Getenv("BIFROEST_TEST_NODE"); node != "" {
		return node
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}
	return node
}

type sharedExecutionExpectation struct {
	exit uint32
	task audit.SessionTask
	pty  bool
}

// The probe reads the native workload ID and marker independently of both SSH
// and browser output. Browser actions use only the real HTTPS/key-WASM/xterm UI.
func exerciseSharedBrowserWorkload(t *testing.T, f *fixture, node, backend string, probe func(*testing.T) (string, string)) {
	t.Helper()
	initial := f.ssh(3*time.Minute, f.clientKey, "e2e", nil,
		`/bin/sh -c 'printf "ssh-owned\n" > /home/e2e/bifroest-web-marker; printf "shared-identifiers-begin\n"; /usr/local/bin/e2e-helper environment; printf "account="; /usr/bin/id -u'`)
	if initial.err != nil {
		t.Fatalf("initial SSH execution: %v\n%s", initial.err, initial.stderr)
	}
	first := parseSharedExecutionIDs(t, initial.stdout)
	if first["session"] == "" || first["connection"] == "" || first["account"] == "" {
		t.Fatalf("missing initial identifiers: %v", first)
	}
	before, marker := probe(t)
	if before == "" || marker != "ssh-owned\n" {
		t.Fatalf("initial workload identity/marker: %q %q", before, marker)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	result := runCommand(ctx, filepath.Join(f.repoRoot, "web"), nil, node, filepath.Join(f.repoRoot, "web", "test", "shared-workload-ui.mjs"), f.browserOrigin, f.clientKey, backend)
	if result.err != nil {
		var producer audit.ProducerId
		if producer.Set(f.recordingProducerID) == nil {
			journal, err := audit.VerifyLiveJournals(t.Context(), []audit.JournalSource{{Name: "default", Directory: filepath.Join(f.tempDir, "auditlog"), ExpectedProducerId: producer, WithSensitive: true}})
			if err != nil {
				t.Logf("failure audit inspection unavailable: %v", err)
			} else {
				for _, r := range journal.Records() {
					t.Logf("failure audit: name=%s outcome=%s reason=%s category=%s session=%s connection=%s", r.Event.Name, r.Event.Outcome, r.Event.Reason, r.Event.ErrorCategory, r.Event.SessionId, r.Event.ConnectionId)
				}
			}
		}
		t.Fatalf("actual %s/browser execution: %v\n%s\n%s", backend, result.err, result.stdout, result.stderr)
	}
	var browser struct {
		Executions []struct {
			Session    string `json:"session"`
			Connection string `json:"connection"`
			Account    string `json:"account"`
		} `json:"executions"`
	}
	if err := json.Unmarshal([]byte(result.stdout), &browser); err != nil {
		t.Fatal(err)
	}
	if len(browser.Executions) != 2 {
		t.Fatalf("got %d browser executions, want two", len(browser.Executions))
	}
	wanted := map[string]sharedExecutionExpectation{first["connection"]: {exit: 0, task: audit.SessionTaskExec}}
	for index, e := range browser.Executions {
		if e.Session != first["session"] || e.Account != first["account"] || e.Connection == "" {
			t.Fatalf("browser actor/session/target mismatch: %+v", e)
		}
		if _, duplicate := wanted[e.Connection]; duplicate {
			t.Fatalf("reattached execution %q", e.Connection)
		}
		expect := sharedExecutionExpectation{task: audit.SessionTaskExec}
		if index == 0 {
			expect.exit = 7
			if backend == "docker" {
				expect.task = audit.SessionTaskShell
				expect.pty = true
			}
		}
		wanted[e.Connection] = expect
	}
	after := f.ssh(30*time.Second, f.clientKey, "e2e", nil,
		`/bin/sh -c 'printf "shared-identifiers-begin\n"; /usr/local/bin/e2e-helper environment; printf "account="; /usr/bin/id -u; printf "marker="; /bin/cat /home/e2e/bifroest-web-marker'`)
	if after.err != nil || !strings.Contains(after.stdout, "marker=web-owned\n") {
		t.Fatalf("SSH after browser logout: %v\n%s\n%s", after.err, after.stdout, after.stderr)
	}
	last := parseSharedExecutionIDs(t, after.stdout)
	if last["session"] != first["session"] || last["account"] != first["account"] || last["connection"] == "" {
		t.Fatalf("SSH session/target changed: %v", last)
	}
	if _, duplicate := wanted[last["connection"]]; duplicate {
		t.Fatal("SSH after logout reused a connection")
	}
	wanted[last["connection"]] = sharedExecutionExpectation{task: audit.SessionTaskExec}
	identity, marker := probe(t)
	if identity != before || marker != "web-owned\n" {
		t.Fatalf("workload changed across browser reload/logout: before=%q after=%q marker=%q", before, identity, marker)
	}
	stopHostBifroest(t, f)
	f.verifySharedExecutionEvidence(t, first["session"], wanted)
	t.Logf("verified %s workload=%s session=%s effective-uid=%s connections=%d exits=0/7/0/0", backend, before, first["session"], first["account"], len(wanted))
}

func parseSharedExecutionIDs(t *testing.T, output string) map[string]string {
	t.Helper()
	const marker = "shared-identifiers-begin\n"
	if strings.Count(output, marker) != 1 {
		t.Fatalf("missing/duplicate ID delimiter: %q", output)
	}
	_, ids, _ := strings.Cut(output, marker)
	return parseEnvironmentIDs(t, ids)
}

func (f *fixture) browserConfiguration(configuration string) (string, error) {
	port, err := unusedTCPPort()
	if err != nil {
		return "", err
	}
	f.browserOrigin = fmt.Sprintf("https://app.example.org:%d", port)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Bifroest owned shared-workload browser fixture"}, DNSNames: []string{"app.example.org"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return "", err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	certPath, keyPath := filepath.Join(f.tempDir, "browser-cert.pem"), filepath.Join(f.tempDir, "browser-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0600); err != nil {
		return "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		return "", err
	}
	needle := "  - name: " + yamlString(f.flowName) + "\n"
	if strings.Count(configuration, needle) != 1 {
		return "", errors.New("ambiguous browser fixture flow")
	}
	configuration = strings.Replace(configuration, needle, needle+"    discoverAsSlug: Work\n", 1)
	return configuration + fmt.Sprintf("\nhttp:\n  enabled: true\n  addresses: [%s]\n  domains: [app.example.org]\n  tls:\n    certificates:\n      - certificateFile: %s\n        privateKeyFile: %s\n", yamlString(fmt.Sprintf("127.0.0.1:%d", port)), yamlString(certPath), yamlString(keyPath)), nil
}

func (f *fixture) verifySharedExecutionEvidence(t *testing.T, session string, wanted map[string]sharedExecutionExpectation) {
	t.Helper()
	var producer audit.ProducerId
	if err := producer.Set(f.recordingProducerID); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(f.tempDir, "recordings", "sealed"))
	if err != nil {
		t.Fatal(err)
	}
	operations := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".bcast") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(f.tempDir, "recordings", "sealed", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if _, err := recording.ExportNativeRecordingCast(bytes.NewReader(data), int64(len(data)), nil, &output, recording.NativeRecordingVerifyOptions{ExpectedProducerId: producer}); err != nil {
			t.Fatal(err)
		}
		v, err := recording.VerifyCast(bytes.NewReader(output.Bytes()), recording.CastVerifyOptions{ExpectedProducerId: producer})
		if err != nil {
			t.Fatal(err)
		}
		connection := v.Metadata.ConnectionId.String()
		expect, found := wanted[connection]
		if !found || operations[connection] != "" || v.Metadata.SessionId.String() != session || v.Metadata.Flow.String() != f.flowName || v.Result.Status != recording.CastStatusCompleted || v.ExitStatus == nil || *v.ExitStatus != expect.exit || !v.Trusted || v.Metadata.Task != expect.task || v.Metadata.Pty != expect.pty {
			t.Fatalf("incorrect shared recording: connection=%s session=%s task=%s pty=%v exit=%v", connection, v.Metadata.SessionId, v.Metadata.Task, v.Metadata.Pty, v.ExitStatus)
		}
		operations[connection] = v.Metadata.OperationId.String()
	}
	if len(operations) != len(wanted) {
		t.Fatalf("got %d verified recordings, want %d", len(operations), len(wanted))
	}
	journal, err := audit.VerifyJournals(t.Context(), []audit.JournalSource{{Name: "default", Directory: filepath.Join(f.tempDir, "auditlog"), ExpectedProducerId: producer, WithSensitive: true}})
	if err != nil {
		t.Fatal(err)
	}
	starts, completed := make(map[string]bool), make(map[string]bool)
	for _, r := range journal.Records() {
		e := r.Event
		expect, found := wanted[e.ConnectionId]
		if !found {
			continue
		}
		if e.Name != audit.EventNameSessionTaskStarted && e.Name != audit.EventNameSessionTaskCompleted {
			continue
		}
		if e.SessionId != session || e.Flow != f.flowName || e.OperationId != operations[e.ConnectionId] || e.SessionTask != expect.task {
			t.Fatalf("incorrect shared task correlation: %+v", e)
		}
		if e.Name == audit.EventNameSessionTaskStarted {
			if starts[e.ConnectionId] {
				t.Fatal("duplicate task start")
			}
			starts[e.ConnectionId] = true
		} else {
			if completed[e.ConnectionId] || e.Outcome != audit.EventOutcomeSuccess || e.ExitCode == nil || *e.ExitCode != int(expect.exit) {
				t.Fatalf("incorrect shared task completion: %+v", e)
			}
			completed[e.ConnectionId] = true
		}
	}
	if len(starts) != len(wanted) || len(completed) != len(wanted) {
		t.Fatalf("incomplete shared audit starts=%d completed=%d wanted=%d", len(starts), len(completed), len(wanted))
	}
}
