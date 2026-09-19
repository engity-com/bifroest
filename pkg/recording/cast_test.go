package recording

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestCastV3GoldenAndVerification(t *testing.T) {
	content, identity, metadata, digest, exitStatus := castV3GoldenTestContent(t)
	require.Equal(t, recordingFormatVector(t, "cast-v3.cast"), content)
	verification, err := VerifyCast(bytes.NewReader(content), CastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, metadata, verification.Metadata)
	require.Equal(t, CastStatusCompleted, verification.Result.Status)
	require.Equal(t, uint64(4), verification.EventCount)
	require.Equal(t, uint64(1), verification.OutputEvents)
	require.Equal(t, uint64(1), verification.ResizeEvents)
	require.Equal(t, uint64(1), verification.MarkerEvents)
	require.Equal(t, exitStatus, *verification.ExitStatus)
	require.Equal(t, digest, verification.Digest)
	require.Equal(t, identity.Fingerprint(), verification.Fingerprint)
	require.True(t, verification.Trusted)
}

func castV3GoldenTestContent(t *testing.T) ([]byte, *audit.Identity, CastMetadata, CastDigest, uint32) {
	t.Helper()
	identity, header, metadata := castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewCastWriter(&output, identity, header, metadata)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(248*time.Millisecond, OutputStreamTerminal, []byte("Welcome to production\r\n")))
	require.NoError(t, writer.WriteResize(1001*time.Millisecond, 132, 43))
	require.NoError(t, writer.WriteMarker(1020*time.Millisecond, "ready"))
	exitStatus := uint32(0)
	digest, err := writer.Seal(2104*time.Millisecond, CastResult{
		Status:  CastStatusCompleted,
		EndedAt: metadata.StartedAt.Add(2104 * time.Millisecond),
	}, &exitStatus)
	require.NoError(t, err)
	return output.Bytes(), identity, metadata, digest, exitStatus
}

func TestCastV3OfficialAsciinemaCompatibility(t *testing.T) {
	asciinema := os.Getenv("ASCIINEMA")
	if asciinema == "" {
		t.Skip("ASCIINEMA is not configured")
	}
	identity, header, metadata := castTestValues(t, true)
	var cast bytes.Buffer
	writer, err := NewCastWriter(&cast, identity, header, metadata)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(100*time.Millisecond, OutputStreamTerminal, []byte("Welcome\r\n")))
	require.NoError(t, writer.WriteOutput(200*time.Millisecond, OutputStreamTerminal, []byte{0xff, '\r', '\n'}))
	require.NoError(t, writer.WriteResize(300*time.Millisecond, 132, 43))
	require.NoError(t, writer.WriteMarker(400*time.Millisecond, "ready"))
	exitStatus := uint32(0)
	_, err = writer.Seal(500*time.Millisecond, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(500 * time.Millisecond)}, &exitStatus)
	require.NoError(t, err)

	convert := func(source []byte, format string) []byte {
		t.Helper()
		command := exec.Command(asciinema, "--quiet", "convert", "--output-format", format, "-", "-")
		command.Stdin = bytes.NewReader(source)
		for _, environment := range os.Environ() {
			if strings.HasPrefix(environment, "GITHUB_TOKEN=") || strings.HasPrefix(environment, "MISE_GITHUB_TOKEN=") {
				continue
			}
			command.Env = append(command.Env, environment)
		}
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		require.NoErrorf(t, err, "asciinema convert failed: %s", stderr.String())
		return stdout.Bytes()
	}

	converted := convert(cast.Bytes(), "asciicast-v3")
	require.Contains(t, string(converted), `"o", "Welcome\r\n"`)
	require.Contains(t, string(converted), `"r", "132x43"`)
	require.Contains(t, string(converted), `"m", "ready"`)
	require.Contains(t, string(converted), `"x", "0"`)
	require.Equal(t, "Welcome\n�\n", string(convert(cast.Bytes(), "txt")))

	identity, header, metadata = castTestValues(t, true)
	header.Terminal.Columns = MaximumCastTerminalDimension
	header.Terminal.Rows = MaximumCastTerminalDimension
	var boundaryCast bytes.Buffer
	writer, err = NewCastWriter(&boundaryCast, identity, header, metadata)
	require.NoError(t, err)
	require.NoError(t, writer.WriteResize(time.Millisecond, MaximumCastTerminalDimension, MaximumCastTerminalDimension))
	exitStatus = MaximumCastExitStatus
	_, err = writer.Seal(2*time.Millisecond, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Millisecond)}, &exitStatus)
	require.NoError(t, err)

	boundaryConverted := convert(boundaryCast.Bytes(), "asciicast-v3")
	require.Contains(t, string(boundaryConverted), `"cols":65535`)
	require.Contains(t, string(boundaryConverted), `"rows":65535`)
	require.Contains(t, string(boundaryConverted), `"r", "65535x65535"`)
	require.Contains(t, string(boundaryConverted), `"x", "2147483647"`)
}

func TestCastEnforcesOfficialAsciinemaNumericRanges(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	header.Terminal.Columns = MaximumCastTerminalDimension + 1
	_, err := NewCastWriter(io.Discard, identity, header, metadata)
	require.ErrorContains(t, err, "terminal dimensions exceed")

	identity, header, metadata = castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewCastWriter(&output, identity, header, metadata)
	require.NoError(t, err)
	before := append([]byte(nil), output.Bytes()...)
	require.ErrorContains(t, writer.WriteResize(time.Millisecond, MaximumCastTerminalDimension+1, 24), "terminal dimensions exceed")
	require.Equal(t, before, output.Bytes())

	exitStatus := MaximumCastExitStatus + 1
	_, err = writer.Seal(time.Millisecond, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Millisecond)}, &exitStatus)
	require.ErrorContains(t, err, "exit status exceeds")
	require.Equal(t, before, output.Bytes())

	require.NoError(t, validateResizeEvent("65535x65535"))
	require.ErrorContains(t, validateResizeEvent("65536x24"), "illegal resize event")
	status, err := parseExitStatus("2147483647")
	require.NoError(t, err)
	require.Equal(t, MaximumCastExitStatus, status)
	_, err = parseExitStatus("2147483648")
	require.ErrorContains(t, err, "illegal exit status")
}

func TestCastTimingRoundingDoesNotAccumulateDrift(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewCastWriter(&output, identity, header, metadata)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(400*time.Microsecond, OutputStreamTerminal, []byte("a")))
	require.NoError(t, writer.WriteOutput(800*time.Microsecond, OutputStreamTerminal, []byte("b")))
	require.NoError(t, writer.WriteOutput(1200*time.Microsecond, OutputStreamTerminal, []byte("c")))
	status := uint32(0)
	require.NotPanics(t, func() {
		_, err = writer.Seal(1600*time.Microsecond, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(1600 * time.Microsecond)}, &status)
	})
	require.NoError(t, err)
	require.Contains(t, output.String(), "[0.000,\"o\",\"a\"]\n[0.001,\"o\",\"b\"]\n[0.000,\"o\",\"c\"]\n[0.001,\"x\",\"0\"]")
}

func TestCastPreservesInvalidUtf8AndNonPtyStderr(t *testing.T) {
	identity, header, metadata := castTestValues(t, false)
	var output bytes.Buffer
	writer, err := NewCastWriter(&output, identity, header, metadata)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Millisecond, OutputStreamStdout, []byte{'o', 'k', '\n'}))
	require.NoError(t, writer.WriteOutput(2*time.Millisecond, OutputStreamStderr, []byte{0xff, 0x00}))
	status := uint32(1)
	_, err = writer.Seal(3*time.Millisecond, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(3 * time.Millisecond)}, &status)
	require.NoError(t, err)
	require.Contains(t, output.String(), `# bifroest:event:v1 {"schema":"bifroest.asciicast-event/v1","sequence":2,"stream":"stderr","raw":"/wA="}`)
	verification, err := VerifyCast(bytes.NewReader(output.Bytes()), CastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, uint64(2), verification.OutputEvents)
}

func TestCastVerificationRejectsTamperingAndTrailingData(t *testing.T) {
	content, identity := sealedCastTestContent(t)
	tampered := bytes.Replace(content, []byte("Welcome"), []byte("Goodbye"), 1)
	_, err := VerifyCast(bytes.NewReader(tampered), CastVerifyOptions{AllowUntrusted: true})
	require.ErrorContains(t, err, "digest")

	withInput := bytes.Replace(content, []byte(`[0.248,"o"`), []byte(`[0.248,"i"`), 1)
	_, err = VerifyCast(bytes.NewReader(withInput), CastVerifyOptions{AllowUntrusted: true})
	require.ErrorContains(t, err, "forbidden input")

	trailing := append(append([]byte(nil), content...), []byte("# trailing\n")...)
	_, err = VerifyCast(bytes.NewReader(trailing), CastVerifyOptions{AllowUntrusted: true})
	require.ErrorContains(t, err, "after its final signature")

	otherIdentity, _, _ := castTestValuesWithSeed(t, true, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	_, err = VerifyCast(bytes.NewReader(content), CastVerifyOptions{ExpectedProducerId: otherIdentity.ProducerId()})
	require.ErrorContains(t, err, "belongs to producer")
	require.NotEqual(t, identity.ProducerId(), otherIdentity.ProducerId())

	lines := bytes.Split(content, []byte{'\n'})
	duplicateLines := make([][]byte, 0, len(lines)+1)
	duplicateLines = append(duplicateLines, lines[:2]...)
	duplicateLines = append(duplicateLines, lines[1])
	duplicateLines = append(duplicateLines, lines[2:]...)
	withDuplicateMetadata := bytes.Join(duplicateLines, []byte{'\n'})
	_, err = VerifyCast(bytes.NewReader(withDuplicateMetadata), CastVerifyOptions{AllowUntrusted: true})
	require.ErrorContains(t, err, "misplaced Bifroest cast comment")
}

func TestCastVerificationRequiresExplicitTrustMode(t *testing.T) {
	content, _ := sealedCastTestContent(t)
	_, err := VerifyCast(bytes.NewReader(content), CastVerifyOptions{})
	require.ErrorContains(t, err, "expected producer ID is required")
	require.True(t, bferrors.Config.IsErr(err))
	verification, err := VerifyCast(bytes.NewReader(content), CastVerifyOptions{AllowUntrusted: true})
	require.NoError(t, err)
	require.False(t, verification.Trusted)
}

func TestCastVerificationEnforcesLineAndTotalSizeLimits(t *testing.T) {
	oversizedLine := strings.Repeat("x", MaximumCastLineBytes+1) + "\n"
	_, err := VerifyCast(strings.NewReader(oversizedLine), CastVerifyOptions{
		MaximumBytes:   int64(len(oversizedLine)),
		AllowUntrusted: true,
	})
	require.ErrorContains(t, err, "line exceeds")
	require.True(t, bferrors.System.IsErr(err))

	content, _ := sealedCastTestContent(t)
	_, err = VerifyCast(bytes.NewReader(content), CastVerifyOptions{
		MaximumBytes:   int64(len(content) - 1),
		AllowUntrusted: true,
	})
	require.ErrorContains(t, err, "cast exceeds")
}

func TestCastVerificationRequiresExactHeaderFieldNames(t *testing.T) {
	content, _ := sealedCastTestContent(t)
	for _, replacement := range [][2]string{
		{`"version":3`, `"Version":3`},
		{`"cols":120`, `"Cols":120`},
	} {
		tampered := bytes.Replace(content, []byte(replacement[0]), []byte(replacement[1]), 1)
		_, err := VerifyCast(bytes.NewReader(tampered), CastVerifyOptions{AllowUntrusted: true})
		require.ErrorContains(t, err, "has no")
	}
}

func TestCastParserAcceptsCompatibleJsonRepresentations(t *testing.T) {
	interval, code, data, err := decodeCastEvent([]byte(`[0.001,"o","\u0061\/"]`))
	require.NoError(t, err)
	require.Equal(t, time.Millisecond, interval)
	require.Equal(t, "o", code)
	require.Equal(t, "a/", data)

	var header CastHeader
	require.NoError(t, decodeCastHeader([]byte(`{"version":3,"term":{"cols":80,"rows":24},"timestamp":1,"future":1e1000}`), &header))
	require.Equal(t, 3, header.Version)
}

func TestCastWriterRejectsInvalidUtf8Metadata(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	header.Terminal.Type = string([]byte{0xff})
	_, err := NewCastWriter(io.Discard, identity, header, metadata)
	require.ErrorContains(t, err, "terminal type is not valid UTF-8")

	identity, header, metadata = castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewCastWriter(&output, identity, header, metadata)
	require.NoError(t, err)
	status := uint32(0)
	_, err = writer.Seal(time.Millisecond, CastResult{
		Status:  CastStatusCompleted,
		EndedAt: metadata.StartedAt.Add(time.Millisecond),
		Reason:  string([]byte{0xff}),
	}, &status)
	require.ErrorContains(t, err, "result reason is not valid UTF-8")
}

func TestCastWriterSplitsLargeUtf8OutputOnRuneBoundaries(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewCastWriter(&output, identity, header, metadata)
	require.NoError(t, err)
	data := append(bytes.Repeat([]byte{'a'}, MaximumOutputEventBytes-1), []byte("€")...)
	data = append(data, 0xff, 'z')
	require.NoError(t, writer.WriteOutput(time.Millisecond, OutputStreamTerminal, data))
	status := uint32(0)
	_, err = writer.Seal(2*time.Millisecond, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Millisecond)}, &status)
	require.NoError(t, err)
	require.Contains(t, output.String(), "€")
	verification, err := VerifyCast(bytes.NewReader(output.Bytes()), CastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, uint64(2), verification.OutputEvents)
}

func TestIdRequiresCanonicalRandomUuid(t *testing.T) {
	var id Id
	require.NoError(t, id.UnmarshalText([]byte("34e34ab8-7457-4d88-a5e4-c57791775c3a")))
	require.Equal(t, "34e34ab8-7457-4d88-a5e4-c57791775c3a", id.String())
	err := id.UnmarshalText([]byte("34E34AB8-7457-4D88-A5E4-C57791775C3A"))
	require.ErrorContains(t, err, "canonical")
	require.True(t, bferrors.Config.IsErr(err))
	err = id.UnmarshalText([]byte("0194c3c8-11b2-7a4c-a49a-7709891742fe"))
	require.ErrorContains(t, err, "illegal")
	require.True(t, bferrors.Config.IsErr(err))
}

func sealedCastTestContent(t *testing.T) ([]byte, *audit.Identity) {
	t.Helper()
	identity, header, metadata := castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewCastWriter(&output, identity, header, metadata)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(248*time.Millisecond, OutputStreamTerminal, []byte("Welcome")))
	status := uint32(0)
	_, err = writer.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, &status)
	require.NoError(t, err)
	return output.Bytes(), identity
}

func castTestValues(t *testing.T, pty bool) (*audit.Identity, CastHeader, CastMetadata) {
	t.Helper()
	return castTestValuesWithSeed(t, pty, recordingFormatVectorSigningSeedHex)
}

func castTestValuesWithSeed(t *testing.T, pty bool, encodedSeed string) (*audit.Identity, CastHeader, CastMetadata) {
	t.Helper()
	seed, err := hex.DecodeString(encodedSeed)
	require.NoError(t, err)
	privateKey, err := bfcrypto.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	identity, err := audit.NewIdentity(privateKey)
	require.NoError(t, err)
	startedAt := time.Date(2026, time.September, 13, 12, 34, 56, 123456789, time.UTC)
	header := CastHeader{
		Version:   castVersion,
		Terminal:  CastTerminal{Columns: 120, Rows: 40, Type: "xterm-256color"},
		Timestamp: startedAt.Unix(),
	}
	var recordingId Id
	require.NoError(t, recordingId.UnmarshalText([]byte("34e34ab8-7457-4d88-a5e4-c57791775c3a")))
	var connectionId connection.Id
	require.NoError(t, connectionId.UnmarshalText([]byte("82d8fdda-4730-43b7-bfde-72733c217bde")))
	var sessionId session.Id
	require.NoError(t, sessionId.UnmarshalText([]byte("6d05798f-b877-4191-8aa0-4576a30411ad")))
	metadata := CastMetadata{
		RecordingId:  recordingId,
		ConnectionId: connectionId,
		SessionId:    sessionId,
		OperationId:  uuid.MustParse("f73ac7c7-ae47-4a6e-878d-e81237773130"),
		Flow:         configuration.FlowName("production"),
		Task:         audit.SessionTaskShell,
		Pty:          pty,
		ProducerId:   identity.ProducerId(),
		StartedAt:    startedAt,
	}
	return identity, header, metadata
}

func TestCastWriterRejectsInvalidOrderingAndStreams(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewCastWriter(&output, identity, header, metadata)
	require.NoError(t, err)
	require.ErrorContains(t, writer.WriteOutput(time.Millisecond, OutputStreamStdout, []byte("wrong")), "terminal output stream")
	require.NoError(t, writer.WriteOutput(2*time.Millisecond, OutputStreamTerminal, []byte("ok")))
	require.ErrorContains(t, writer.WriteOutput(time.Millisecond, OutputStreamTerminal, []byte("late")), "moved backwards")
	_, err = writer.Seal(3*time.Millisecond, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt}, nil)
	require.ErrorContains(t, err, "no exit status")
	require.False(t, strings.Contains(output.String(), "late"))
}

func TestCastWriterDoesNotMutateOutputForRejectedAnnotatedWrites(t *testing.T) {
	identity, header, metadata := castTestValues(t, false)
	var output bytes.Buffer
	writer, err := NewCastWriter(&output, identity, header, metadata)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(2*time.Millisecond, OutputStreamStdout, []byte("ok")))
	beforeRejectedWrite := append([]byte(nil), output.Bytes()...)
	require.ErrorContains(t, writer.WriteOutput(time.Millisecond, OutputStreamStderr, []byte{0xff}), "moved backwards")
	require.Equal(t, beforeRejectedWrite, output.Bytes())

	status := uint32(0)
	_, err = writer.Seal(3*time.Millisecond, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(3 * time.Millisecond)}, &status)
	require.NoError(t, err)
	sealed := append([]byte(nil), output.Bytes()...)
	require.ErrorContains(t, writer.WriteOutput(4*time.Millisecond, OutputStreamStderr, []byte{0xff}), "already sealed")
	require.Equal(t, sealed, output.Bytes())
}

func TestCastEventEscapesNonPrintableUnicode(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewCastWriter(&output, identity, header, metadata)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Millisecond, OutputStreamTerminal, []byte("before\u007f\u0085\u200b\u202eafter")))
	status := uint32(0)
	_, err = writer.Seal(2*time.Millisecond, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Millisecond)}, &status)
	require.NoError(t, err)
	require.Contains(t, output.String(), `"before\u007f\u0085\u200b\u202eafter"`)
	_, err = VerifyCast(bytes.NewReader(output.Bytes()), CastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
}

func TestCastParserRejectsUnpairedUnicodeSurrogates(t *testing.T) {
	_, _, _, err := decodeCastEvent([]byte(`[0.001,"o","\ud800"]`))
	require.ErrorContains(t, err, "unpaired high surrogate")
	_, _, _, err = decodeCastEvent([]byte(`[0.001,"o","\udc00"]`))
	require.ErrorContains(t, err, "unpaired low surrogate")
	_, _, data, err := decodeCastEvent([]byte(`[0.001,"o","\ud83d\ude00"]`))
	require.NoError(t, err)
	require.Equal(t, "😀", data)

	var header CastHeader
	err = decodeCastHeader([]byte(`{"version":3,"term":{"cols":80,"rows":24,"type":"\ud800"},"timestamp":1}`), &header)
	require.ErrorContains(t, err, "unpaired high surrogate")
}

type limitedCastTestWriter struct {
	bytes.Buffer
	maximum int
}

func (this *limitedCastTestWriter) Write(value []byte) (int, error) {
	remaining := this.maximum - this.Len()
	if remaining <= 0 {
		return 0, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
	}
	return this.Buffer.Write(value)
}

func TestCastWriterIsPoisonedAfterShortWrite(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	output := &limitedCastTestWriter{maximum: MaximumCastLineBytes}
	writer, err := NewCastWriter(output, identity, header, metadata)
	require.NoError(t, err)
	output.maximum = output.Len() + 5
	err = writer.WriteOutput(time.Millisecond, OutputStreamTerminal, []byte("too long"))
	require.ErrorIs(t, err, io.ErrShortWrite)
	require.True(t, bferrors.System.IsErr(err))
	written := output.Len()
	require.ErrorIs(t, writer.WriteMarker(2*time.Millisecond, "ignored"), io.ErrShortWrite)
	require.Equal(t, written, output.Len())
}
