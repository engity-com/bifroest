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
	beforeWrite        func() // Test hook for changes after inspection and before output.
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
	Status               recording.CastStatus      `json:"status,omitempty"`
	CastDigest           string                    `json:"castDigest,omitempty"`
	ClaimedStatus        recording.CastStatus      `json:"claimedStatus,omitempty"`
	ClaimedCastDigest    string                    `json:"claimedCastDigest,omitempty"`
	ChunkCount           uint64                    `json:"chunkCount,omitempty"`
	CastBytes            uint64                    `json:"castBytes"`
	RecipientFingerprint string                    `json:"recipientFingerprint,omitempty"`
	Cast                 *recordingInspectCast     `json:"cast,omitempty"`
}

type recordingInspectSignature struct {
	Valid       bool   `json:"valid"`
	Trusted     bool   `json:"trusted"`
	Fingerprint string `json:"fingerprint"`
}

type recordingInspectCast struct {
	EventCount   uint64 `json:"eventCount"`
	OutputEvents uint64 `json:"outputEvents"`
	ResizeEvents uint64 `json:"resizeEvents"`
	MarkerEvents uint64 `json:"markerEvents"`
}

func registerRecordingInspectCmd(parent *kingpin.CmdClause) {
	opts := recordingInspectOpts{}
	cmd := parent.Command("inspect", "Verify and inspect a session Recording artifact as JSON.").
		Action(func(*kingpin.ParseContext) error { return doRecordingInspect(&opts, stdos.Stdout) })
	cmd.Flag("expectedProducerId", "Trusted producer ID containing exactly 64 hexadecimal characters.").
		PlaceHolder("<producer-id>").
		StringVar(&opts.expectedProducerId)
	cmd.Arg("file", "Sealed .bcast or .becast Recording artifact, or signed standalone .cast.").
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
	file, initial, err := openRecordingInput(opts.file)
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
	if err := validateRecordingInput(opts.file, file, initial); err != nil {
		return err
	}
	if err := ensureRecordingStandardOutputSafe(stdout, file, nil); err != nil {
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
	if opts.beforeWrite != nil {
		opts.beforeWrite()
	}
	if err := validateRecordingInput(opts.file, file, initial); err != nil {
		return err
	}
	if _, err := stdout.Write(encoded.Bytes()); err != nil {
		return fmt.Errorf("cannot write Recording inspection: %w", err)
	}
	return nil
}

func openRecordingInput(path string) (*stdos.File, stdos.FileInfo, error) {
	if strings.TrimSpace(path) == "" || path == "-" {
		return nil, nil, fmt.Errorf("recording command requires a file path")
	}
	initial, err := stdos.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot inspect Recording input %q: %w", path, err)
	}
	if initial.Mode()&stdos.ModeSymlink != 0 || !initial.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("recording input %q must be a regular non-symlink file", path)
	}
	file, err := openRecordingFile(path)
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

func validateRecordingInput(path string, file *stdos.File, initial stdos.FileInfo) error {
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("cannot recheck Recording input %q: %w", path, err)
	}
	current, err := stdos.Lstat(path)
	if err != nil {
		return fmt.Errorf("cannot recheck Recording input %q: %w", path, err)
	}
	if current.Mode()&stdos.ModeSymlink != 0 || !current.Mode().IsRegular() || !stdos.SameFile(initial, opened) || !stdos.SameFile(initial, current) || opened.Size() != initial.Size() || current.Size() != initial.Size() || opened.Mode() != initial.Mode() || current.Mode() != initial.Mode() || !opened.ModTime().Equal(initial.ModTime()) || !current.ModTime().Equal(initial.ModTime()) {
		return fmt.Errorf("recording input %q changed while being processed", path)
	}
	return nil
}

func newRecordingInspectOutput(inspection *recording.Inspection, size int64) (*recordingInspectOutput, error) {
	if inspection == nil {
		return nil, fmt.Errorf("nil Recording inspection")
	}
	result := &recordingInspectOutput{Schema: recordingInspectionSchema, Format: inspection.Format, ContainerBytes: size}
	switch inspection.Format {
	case recording.FormatBcast, recording.FormatBECastCBOR:
		if inspection.Native == nil {
			return nil, fmt.Errorf("recording inspection has no native result")
		}
		native := inspection.Native
		publicKey, err := ssh.ParsePublicKey(native.Header.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("cannot inspect native Recording signing key: %w", err)
		}
		var status recording.CastStatus
		switch native.Seal.Status {
		case 1:
			status = recording.CastStatusCompleted
		case 2:
			status = recording.CastStatusFailed
		case 3:
			status = recording.CastStatusIncomplete
		default:
			return nil, fmt.Errorf("invalid native Recording status")
		}
		result.Compressed = true
		result.Encrypted = native.Header.Encryption == 1
		result.Signature = recordingInspectSignature{Valid: true, Trusted: native.Trusted, Fingerprint: ssh.FingerprintSHA256(publicKey)}
		result.RecordingId = recording.Id(native.Header.RecordingId).String()
		result.ProducerId = audit.ProducerId(native.Header.ProducerId).String()
		result.ChunkCount = native.Seal.ChunkCount
		result.CastBytes = native.Seal.CastBytes
		if result.Encrypted {
			result.VerificationScope = "outer"
			result.ClaimedStatus = status
			result.ClaimedCastDigest = recording.CastDigest(native.Seal.CastDigest).String()
			result.RecipientFingerprint = native.Header.Recipient
		} else {
			result.VerificationScope = "full"
			result.Status = status
			result.CastDigest = recording.CastDigest(native.Seal.CastDigest).String()
		}
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
	default:
		return nil, fmt.Errorf("unsupported Recording inspection format %q", inspection.Format)
	}
	return result, nil
}

func newRecordingInspectCast(verification *recording.CastVerification) *recordingInspectCast {
	return &recordingInspectCast{
		EventCount:   verification.EventCount,
		OutputEvents: verification.OutputEvents,
		ResizeEvents: verification.ResizeEvents,
		MarkerEvents: verification.MarkerEvents,
	}
}
