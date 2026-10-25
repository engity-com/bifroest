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

// This starts the existing owned kind/Podman-or-Docker fixture; it never adopts
// the user's kubeconfig context or creates resources in an unrelated cluster.
func TestOpenSSHKubernetesBrowserSharedWorkload(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_BROWSER_UI") != "1" {
		t.Skip("set BIFROEST_TEST_BROWSER_UI=1 after mise run build:web and browser installation")
	}
	node := os.Getenv("BIFROEST_TEST_NODE")
	if node == "" {
		var err error
		node, err = exec.LookPath("node")
		if err != nil {
			t.Fatal(err)
		}
	}
	k, err := newKubernetesExecutionFixture(t, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("runtime=%s owned-cluster=%s namespace=%s", k.runtimeCLI, k.clusterName, k.namespace)
	initial := k.ssh(3*time.Minute, k.clientKey, "e2e", nil,
		`/bin/sh -c 'printf "ssh-owned\n" > /home/e2e/bifroest-web-marker; printf "shared-identifiers-begin\n"; /usr/local/bin/e2e-helper environment; printf "account="; id -u'`)
	if initial.err != nil {
		t.Fatalf("initial SSH execution: %v\n%s", initial.err, initial.stderr)
	}
	first := parseSharedExecutionIDs(t, initial.stdout)
	if first["session"] == "" || first["connection"] == "" || first["account"] == "" {
		t.Fatalf("missing initial identifiers: %v", first)
	}
	if err := k.waitForEnvironmentPod(); err != nil {
		t.Fatal(err)
	}
	before := k.podExec(10*time.Second, "cat", "/home/e2e/bifroest-web-marker")
	if before.err != nil || before.stdout != "ssh-owned\n" {
		t.Fatalf("initial Pod marker: %v %q", before.err, before.stdout)
	}
	podBefore := k.kubectl(10*time.Second, "get", "pod", k.environmentPod, "-n", k.namespace, "-o", "jsonpath={.metadata.uid}")
	if podBefore.err != nil || strings.TrimSpace(podBefore.stdout) == "" {
		t.Fatalf("initial Pod UID: %v", podBefore.err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	result := runCommand(ctx, filepath.Join(k.repoRoot, "web"), nil, node,
		filepath.Join(k.repoRoot, "web", "test", "kubernetes-ui.mjs"), k.browserOrigin, k.clientKey)
	if result.err != nil {
		var producer audit.ProducerId
		if producer.Set(k.recordingProducerID) == nil {
			journal, inspectErr := audit.VerifyLiveJournals(t.Context(), []audit.JournalSource{{Name: "default", Directory: filepath.Join(k.tempDir, "auditlog"), ExpectedProducerId: producer, WithSensitive: true}})
			if inspectErr != nil {
				t.Logf("failure audit inspection unavailable: %v", inspectErr)
			} else {
				for _, record := range journal.Records() {
					t.Logf("failure audit: name=%s outcome=%s reason=%s category=%s session=%s connection=%s", record.Event.Name, record.Event.Outcome, record.Event.Reason, record.Event.ErrorCategory, record.Event.SessionId, record.Event.ConnectionId)
				}
			}
		}
		t.Fatalf("actual Kubernetes/browser execution: %v\n%s\n%s", result.err, result.stdout, result.stderr)
	}
	var browser struct {
		Executions []struct {
			Session    string `json:"session"`
			Connection string `json:"connection"`
			Account    string `json:"account"`
		} `json:"executions"`
	}
	if err := json.Unmarshal([]byte(result.stdout), &browser); err != nil {
		t.Fatalf("decode browser result: %v", err)
	}
	if len(browser.Executions) != 2 {
		t.Fatalf("got %d browser executions, want two", len(browser.Executions))
	}
	wanted := map[string]uint32{first["connection"]: 0}
	for index, execution := range browser.Executions {
		if execution.Session != first["session"] || execution.Account != first["account"] || execution.Connection == "" {
			t.Fatalf("browser execution does not share verified actor/session/target: %+v", execution)
		}
		if _, duplicate := wanted[execution.Connection]; duplicate {
			t.Fatalf("browser execution reattached connection %q", execution.Connection)
		}
		wanted[execution.Connection] = 0
		if index == 0 {
			wanted[execution.Connection] = 7
		}
	}
	// Browser logout must preserve both the workload marker and the persistent
	// session, while the next SSH connection starts another distinct execution.
	after := k.ssh(30*time.Second, k.clientKey, "e2e", nil,
		`/bin/sh -c 'printf "shared-identifiers-begin\n"; /usr/local/bin/e2e-helper environment; printf "account="; id -u; printf "marker="; cat /home/e2e/bifroest-web-marker'`)
	if after.err != nil || !strings.Contains(after.stdout, "web-owned\n") {
		t.Fatalf("SSH after browser logout: %v\n%s\n%s", after.err, after.stdout, after.stderr)
	}
	last := parseSharedExecutionIDs(t, after.stdout)
	if last["session"] != first["session"] || last["account"] != first["account"] || last["connection"] == "" {
		t.Fatalf("SSH session/target changed after logout: %v", last)
	}
	if _, duplicate := wanted[last["connection"]]; duplicate {
		t.Fatal("SSH after logout reused an execution connection")
	}
	wanted[last["connection"]] = 0
	pods, err := k.podNames()
	if err != nil || len(pods) != 1 || pods[0] != k.environmentPod {
		t.Fatalf("shared Pod changed: %v %v", pods, err)
	}
	podAfter := k.kubectl(10*time.Second, "get", "pod", k.environmentPod, "-n", k.namespace, "-o", "jsonpath={.metadata.uid}")
	if podAfter.err != nil || podAfter.stdout != podBefore.stdout {
		t.Fatalf("shared Pod UID changed: %v", podAfter.err)
	}
	stopHostBifroest(t, k.fixture)
	k.verifySharedExecutionEvidence(t, first["session"], wanted)
}

func parseSharedExecutionIDs(t *testing.T, output string) map[string]string {
	t.Helper()
	// First execution may emit real image/provisioning notices before the
	// helper runs. Only the exact command-delimited suffix contains test IDs.
	const marker = "shared-identifiers-begin\n"
	if strings.Count(output, marker) != 1 {
		t.Fatalf("missing or duplicate execution-ID delimiter: %q", output)
	}
	_, ids, _ := strings.Cut(output, marker)
	return parseEnvironmentIDs(t, ids)
}

func (k *kubernetesFixture) browserConfiguration(configuration string) (string, error) {
	port, err := unusedTCPPort()
	if err != nil {
		return "", err
	}
	k.browserOrigin = fmt.Sprintf("https://app.example.org:%d", port)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Bifröst owned Kubernetes browser fixture"}, DNSNames: []string{"app.example.org"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return "", err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	certPath, keyPath := filepath.Join(k.tempDir, "browser-cert.pem"), filepath.Join(k.tempDir, "browser-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0600); err != nil {
		return "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		return "", err
	}
	needle := "  - name: " + yamlString(k.flowName) + "\n"
	if strings.Count(configuration, needle) != 1 {
		return "", errors.New("ambiguous browser fixture flow")
	}
	configuration = strings.Replace(configuration, needle, needle+"    discoverAsSlug: Work\n", 1)
	return configuration + fmt.Sprintf("\nhttp:\n  enabled: true\n  addresses: [%s]\n  domains: [app.example.org]\n  tls:\n    certificates:\n      - certificateFile: %s\n        privateKeyFile: %s\n", yamlString(fmt.Sprintf("127.0.0.1:%d", port)), yamlString(certPath), yamlString(keyPath)), nil
}

func (k *kubernetesFixture) verifySharedExecutionEvidence(t *testing.T, session string, wanted map[string]uint32) {
	t.Helper()
	var producer audit.ProducerId
	if err := producer.Set(k.recordingProducerID); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(k.tempDir, "recordings", "sealed"))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".bcast") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(k.tempDir, "recordings", "sealed", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		_, err = recording.ExportNativeRecordingCast(bytes.NewReader(data), int64(len(data)), nil, &output, recording.NativeRecordingVerifyOptions{ExpectedProducerId: producer})
		if err != nil {
			t.Fatalf("verify native execution recording: %v", err)
		}
		verified, err := recording.VerifyCast(bytes.NewReader(output.Bytes()), recording.CastVerifyOptions{ExpectedProducerId: producer})
		if err != nil {
			t.Fatal(err)
		}
		connection := verified.Metadata.ConnectionId.String()
		exit, found := wanted[connection]
		if !found || seen[connection] || verified.Metadata.SessionId.String() != session || verified.Result.Status != recording.CastStatusCompleted || verified.ExitStatus == nil || *verified.ExitStatus != exit || !verified.Trusted {
			t.Fatalf("incorrect shared execution recording: connection=%s session=%s exit=%v", connection, verified.Metadata.SessionId, verified.ExitStatus)
		}
		seen[connection] = true
	}
	if len(seen) != len(wanted) {
		t.Fatalf("got %d verified recordings, want %d", len(seen), len(wanted))
	}
	journal, err := audit.VerifyJournals(t.Context(), []audit.JournalSource{{Name: "default", Directory: filepath.Join(k.tempDir, "auditlog"), ExpectedProducerId: producer, WithSensitive: true}})
	if err != nil {
		t.Fatalf("verify shared audit journal: %v", err)
	}
	completed := make(map[string]bool)
	for _, record := range journal.Records() {
		if _, found := wanted[record.Event.ConnectionId]; found && record.Event.Name == audit.EventNameSessionTaskCompleted {
			if record.Event.SessionId != session || completed[record.Event.ConnectionId] {
				t.Fatalf("incorrect shared task audit correlation: %+v", record.Event)
			}
			completed[record.Event.ConnectionId] = true
		}
	}
	if len(completed) != len(wanted) {
		t.Fatalf("got %d audited task completions, want %d", len(completed), len(wanted))
	}
}
