//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func recordingProducerID(t *testing.T, identityPath string) string {
	t.Helper()
	privateKey, err := bfcrypto.LoadSecurePrivateKeyFile(identityPath, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := audit.NewIdentity(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return identity.ProducerId().String()
}

func sealedSessionRecordingArtifact(t *testing.T, recordingDirectory string) string {
	t.Helper()
	var artifact string
	if err := poll(5*time.Second, func() error {
		sealedDirectory := filepath.Join(recordingDirectory, "sealed")
		entries, err := os.ReadDir(sealedDirectory)
		if err != nil {
			return err
		}
		artifacts := make([]string, 0, len(entries))
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".cast.zst") {
				artifacts = append(artifacts, entry.Name())
			}
		}
		if len(artifacts) != 1 {
			return fmt.Errorf("got %d sealed recordings, want one: %v", len(artifacts), artifacts)
		}
		artifact = filepath.Join(sealedDirectory, artifacts[0])
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return artifact
}

func stopHostBifroest(t *testing.T, f *fixture) {
	t.Helper()
	if f.bifroestProc == nil {
		t.Fatal("Bifroest process is not running")
	}
	if exited, err := f.bifroestProc.collect(); exited {
		t.Fatalf("Bifroest exited before recording verification: %v", err)
	}
	if err := f.bifroestProc.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal Bifroest: %v", err)
	}
	if err := f.bifroestProc.wait(10 * time.Second); err != nil {
		t.Fatalf("wait for graceful Bifroest shutdown: %v\nstdout:\n%s\nstderr:\n%s", err, f.bifroestProc.stdout.String(), f.bifroestProc.stderr.String())
	}
}

func verifySessionRecordingArtifact(t *testing.T, f *fixture, artifact, producerID string) {
	t.Helper()
	wrongProducerID := strings.Repeat("f", 64)
	if wrongProducerID == producerID {
		wrongProducerID = strings.Repeat("e", 64)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	result := runCommand(ctx, f.repoRoot, nil, f.bifroest, "recording", "inspect", "--expectedProducerId", wrongProducerID, artifact)
	cancel()
	if result.err == nil || result.stdout != "" {
		t.Fatalf("inspection with wrong producer did not fail closed: error=%v stdout=%q", result.err, result.stdout)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	result = runCommand(ctx, f.repoRoot, nil, f.bifroest, "recording", "inspect", "--expectedProducerId", producerID, artifact)
	cancel()
	if result.err != nil {
		t.Fatalf("inspect sealed recording: %v\nstderr:\n%s", result.err, result.stderr)
	}
	var inspection struct {
		Schema            string `json:"schema"`
		Format            string `json:"format"`
		VerificationScope string `json:"verificationScope"`
		ProducerID        string `json:"producerId"`
		Status            string `json:"status"`
		Signature         struct {
			Valid   bool `json:"valid"`
			Trusted bool `json:"trusted"`
		} `json:"signature"`
		Cast *struct {
			ExitStatus   *uint32 `json:"exitStatus"`
			OutputEvents uint64  `json:"outputEvents"`
		} `json:"cast"`
	}
	if err := json.Unmarshal([]byte(result.stdout), &inspection); err != nil {
		t.Fatalf("decode recording inspection: %v\noutput:\n%s", err, result.stdout)
	}
	if inspection.Schema != "bifroest.session-recording-inspection/v1" || inspection.Format != "cast-zstd/v1" || inspection.VerificationScope != "full" {
		t.Fatalf("unexpected recording inspection: schema=%q format=%q scope=%q", inspection.Schema, inspection.Format, inspection.VerificationScope)
	}
	if inspection.ProducerID != producerID || !inspection.Signature.Valid || !inspection.Signature.Trusted {
		t.Fatalf("untrusted recording inspection: producer=%q valid=%v trusted=%v", inspection.ProducerID, inspection.Signature.Valid, inspection.Signature.Trusted)
	}
	if inspection.Status != "completed" || inspection.Cast == nil || inspection.Cast.ExitStatus == nil || *inspection.Cast.ExitStatus != 23 || inspection.Cast.OutputEvents == 0 {
		t.Fatalf("unexpected recorded result: status=%q cast=%+v", inspection.Status, inspection.Cast)
	}

	exported := filepath.Join(t.TempDir(), "session.cast")
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	result = runCommand(ctx, f.repoRoot, nil, f.bifroest, "recording", "export", "--expectedProducerId", producerID, "--output", exported, artifact)
	cancel()
	if result.err != nil {
		t.Fatalf("export sealed recording: %v\nstderr:\n%s", result.err, result.stderr)
	}
	cast, err := os.ReadFile(exported)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{[]byte("stdout-e2e"), []byte("stderr-e2e")} {
		if !bytes.Contains(cast, expected) {
			t.Errorf("exported Cast does not contain %q", expected)
		}
	}
}
