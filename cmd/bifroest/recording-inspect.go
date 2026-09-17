package main

import (
	"bytes"
	"context"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"io"
	stdos "os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/recording"
)

const recordingInspectionSchema = "bifroest.session-recording-inspection/v1"

type recordingInspectOpts struct {
	file               string
	expectedProducerId string
}

type recordingInspectOutput struct {
	Schema               string                    `json:"schema"`
	Format               recording.Format          `json:"format"`
	ContainerBytes       int64                     `json:"containerBytes"`
	Encrypted            bool                      `json:"encrypted"`
	Compressed           bool                      `json:"compressed"`
	VerificationScope    string                    `json:"verificationScope"`
	Signature            recordingInspectSignature `json:"signature"`
	RecordingId          string                    `json:"recordingId"`
	ProducerId           string                    `json:"producerId"`
	Status               recording.CastStatus      `json:"status"`
	CastDigest           string                    `json:"castDigest"`
	ChunkCount           uint64                    `json:"chunkCount,omitempty"`
	CastBytes            uint64                    `json:"castBytes"`
	ZstdBytes            uint64                    `json:"zstdBytes,omitempty"`
	CiphertextBytes      uint64                    `json:"ciphertextBytes,omitempty"`
	StreamHash           string                    `json:"streamHash,omitempty"`
	RecipientFingerprint string                    `json:"recipientFingerprint,omitempty"`
	Cast                 *recordingInspectCast     `json:"cast,omitempty"`
}

type recordingInspectSignature struct {
	Valid       bool   `json:"valid"`
	Trusted     bool   `json:"trusted"`
	Fingerprint string `json:"fingerprint"`
}

type recordingInspectCast struct {
	Header       recording.CastHeader   `json:"header"`
	Metadata     recording.CastMetadata `json:"metadata"`
	Result       recording.CastResult   `json:"result"`
	ExitStatus   *uint32                `json:"exitStatus"`
	EventCount   uint64                 `json:"eventCount"`
	OutputEvents uint64                 `json:"outputEvents"`
	ResizeEvents uint64                 `json:"resizeEvents"`
	MarkerEvents uint64                 `json:"markerEvents"`
	Digest       string                 `json:"digest"`
}

func registerRecordingInspectCmd(parent *kingpin.CmdClause) {
	opts := recordingInspectOpts{}
	cmd := parent.Command("inspect", "Verify and inspect a session Recording artifact as JSON.").
		Action(func(*kingpin.ParseContext) error { return doRecordingInspect(&opts, stdos.Stdout) })
	cmd.Flag("expectedProducerId", "Trusted producer ID containing exactly 64 hexadecimal characters.").
		PlaceHolder("<producer-id>").
		StringVar(&opts.expectedProducerId)
	cmd.Arg("file", "Sealed .cast, .cast.zst, or .becast Recording artifact.").
		Required().
		StringVar(&opts.file)
}

func doRecordingInspect(opts *recordingInspectOpts, stdout io.Writer) (rErr error) {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	if stdout == nil {
		return fmt.Errorf("nil stdout")
	}
	var expectedProducerId audit.ProducerId
	allowUntrusted := opts.expectedProducerId == ""
	if !allowUntrusted {
		if err := expectedProducerId.Set(opts.expectedProducerId); err != nil {
			return fmt.Errorf("illegal --expectedProducerId: %w", err)
		}
		if expectedProducerId.IsZero() {
			return fmt.Errorf("--expectedProducerId must not be zero")
		}
	}
	file, initial, err := openRecordingInspectionInput(opts.file)
	if err != nil {
		return err
	}
	defer func() { rErr = goerrors.Join(rErr, file.Close()) }()
	inspection, err := recording.Inspect(file, initial.Size(), recording.InspectOptions{
		Context:            context.Background(),
		ExpectedProducerId: expectedProducerId,
		AllowUntrusted:     allowUntrusted,
	})
	if err != nil {
		return fmt.Errorf("cannot inspect Recording %q: %w", opts.file, err)
	}
	if err := validateRecordingInspectionInput(opts.file, file, initial); err != nil {
		return err
	}
	result, err := newRecordingInspectOutput(inspection, initial.Size())
	if err != nil {
		return err
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("cannot encode Recording inspection: %w", err)
	}
	if _, err := stdout.Write(encoded.Bytes()); err != nil {
		return fmt.Errorf("cannot write Recording inspection: %w", err)
	}
	return nil
}

func openRecordingInspectionInput(path string) (*stdos.File, stdos.FileInfo, error) {
	if strings.TrimSpace(path) == "" || path == "-" {
		return nil, nil, fmt.Errorf("recording inspection requires a file path")
	}
	initial, err := stdos.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot inspect Recording input %q: %w", path, err)
	}
	if initial.Mode()&stdos.ModeSymlink != 0 || !initial.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("recording input %q must be a regular non-symlink file", path)
	}
	file, err := openRecordingInspectionFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot open Recording input %q: %w", path, err)
	}
	opened, err := file.Stat()
	if err != nil || !stdos.SameFile(initial, opened) {
		return nil, nil, goerrors.Join(fmt.Errorf("recording input %q changed while opening", path), err, file.Close())
	}
	if opened.Size() < 1 {
		return nil, nil, goerrors.Join(fmt.Errorf("recording input %q is empty", path), file.Close())
	}
	return file, initial, nil
}

func validateRecordingInspectionInput(path string, file *stdos.File, initial stdos.FileInfo) error {
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("cannot recheck Recording input %q: %w", path, err)
	}
	current, err := stdos.Lstat(path)
	if err != nil {
		return fmt.Errorf("cannot recheck Recording input %q: %w", path, err)
	}
	if current.Mode()&stdos.ModeSymlink != 0 || !current.Mode().IsRegular() || !stdos.SameFile(initial, opened) || !stdos.SameFile(initial, current) || opened.Size() != initial.Size() || current.Size() != initial.Size() || opened.Mode() != initial.Mode() || current.Mode() != initial.Mode() || !opened.ModTime().Equal(initial.ModTime()) || !current.ModTime().Equal(initial.ModTime()) {
		return fmt.Errorf("recording input %q changed while being inspected", path)
	}
	return nil
}

func newRecordingInspectOutput(inspection *recording.Inspection, size int64) (*recordingInspectOutput, error) {
	if inspection == nil {
		return nil, fmt.Errorf("nil Recording inspection")
	}
	result := &recordingInspectOutput{Schema: recordingInspectionSchema, Format: inspection.Format, ContainerBytes: size}
	switch inspection.Format {
	case recording.FormatCast:
		if inspection.Cast == nil {
			return nil, fmt.Errorf("recording inspection has no Cast result")
		}
		result.VerificationScope = "full"
		result.Signature = recordingInspectSignature{Valid: true, Trusted: inspection.Cast.Trusted, Fingerprint: inspection.Cast.Fingerprint}
		result.RecordingId = inspection.Cast.Metadata.RecordingId.String()
		result.ProducerId = inspection.Cast.Metadata.ProducerId.String()
		result.Status = inspection.Cast.Result.Status
		result.CastDigest = inspection.Cast.Digest.String()
		result.CastBytes = uint64(size)
		result.Cast = newRecordingInspectCast(inspection.Cast)
	case recording.FormatCastZstd:
		if inspection.CastZstd == nil || inspection.Cast == nil {
			return nil, fmt.Errorf("recording inspection has no Cast Zstandard result")
		}
		summary := inspection.CastZstd.Summary
		result.Compressed = true
		result.VerificationScope = "full"
		result.Signature = recordingInspectSignature{Valid: true, Trusted: inspection.CastZstd.Trusted, Fingerprint: inspection.CastZstd.Fingerprint}
		result.RecordingId = summary.RecordingId.String()
		result.ProducerId = summary.ProducerId.String()
		result.Status = summary.Status
		result.CastDigest = summary.Digest.String()
		result.ChunkCount = summary.ChunkCount
		result.CastBytes = summary.CastBytes
		result.ZstdBytes = summary.ZstdBytes
		result.StreamHash = summary.StreamHash.String()
		result.Cast = newRecordingInspectCast(inspection.Cast)
	case recording.FormatBECast:
		if inspection.BECast == nil {
			return nil, fmt.Errorf("recording inspection has no BECast result")
		}
		publicKey, err := ssh.ParsePublicKey(inspection.BECast.Header.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("cannot inspect BECast signing key: %w", err)
		}
		summary := inspection.BECast.Summary
		result.Encrypted = true
		result.Compressed = true
		result.VerificationScope = "outer"
		result.Signature = recordingInspectSignature{Valid: true, Trusted: inspection.BECast.Trusted, Fingerprint: ssh.FingerprintSHA256(publicKey)}
		result.RecordingId = summary.RecordingId.String()
		result.ProducerId = summary.ProducerId.String()
		result.Status = summary.Status
		result.CastDigest = summary.Digest.String()
		result.ChunkCount = summary.ChunkCount
		result.CastBytes = summary.CastBytes
		result.CiphertextBytes = summary.CiphertextBytes
		result.StreamHash = summary.CiphertextStreamHash.String()
		result.RecipientFingerprint = summary.RecipientFingerprint
	default:
		return nil, fmt.Errorf("unsupported Recording inspection format %q", inspection.Format)
	}
	return result, nil
}

func newRecordingInspectCast(verification *recording.CastVerification) *recordingInspectCast {
	return &recordingInspectCast{
		Header:       verification.Header,
		Metadata:     verification.Metadata,
		Result:       verification.Result,
		ExitStatus:   verification.ExitStatus,
		EventCount:   verification.EventCount,
		OutputEvents: verification.OutputEvents,
		ResizeEvents: verification.ResizeEvents,
		MarkerEvents: verification.MarkerEvents,
		Digest:       verification.Digest.String(),
	}
}
