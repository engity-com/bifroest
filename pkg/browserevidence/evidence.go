// Package browserevidence composes the shared portable evidence verifiers for
// an owned tab-local worker. It opens no network, filesystem or server actions.
package browserevidence

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"strconv"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/browserkey"
	"github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/nativeformat"
	"github.com/engity-com/bifroest/pkg/recording/cast"
)

const MaximumInputBytes int64 = 64 << 20
const MaximumOutputBytes int64 = 64 << 20

var (
	ErrInput        = errors.New("invalid browser evidence input")
	ErrKey          = errors.New("browser evidence key import failed")
	ErrLimit        = errors.New("browser evidence resource limit")
	ErrVerification = errors.New("browser evidence verification failed")
)

type File struct {
	Name string
	Data []byte
}

type Options struct {
	Producer       string `json:"producer"`
	AllowUntrusted bool   `json:"allowUntrusted"`
	Recipient      string `json:"recipient"`
	Level          string `json:"level"` // outer or private
	Export         bool   `json:"export"`
	Sensitive      bool   `json:"sensitive"`
	AuditScope     string `json:"auditScope"` // complete or captured-prefix
}

type Result struct {
	Kind              string `json:"kind"`
	Validation        string `json:"validation"`
	Trust             string `json:"trust"`
	Producer          string `json:"producer"`
	ExpectedRecipient string `json:"expectedRecipient"`
	Decryption        string `json:"decryption"`
	RecordingID       string `json:"recordingId"`
	AuditScope        string `json:"auditScope"`
	Records           string `json:"records"`
	PrivateRecords    string `json:"privateRecords"`
	OutputFormat      string `json:"outputFormat"`
	Output            []byte `json:"-"`
}

type boundedOutput struct{ data bytes.Buffer }

func (b *boundedOutput) Len() int      { return b.data.Len() }
func (b *boundedOutput) Bytes() []byte { return b.data.Bytes() }

func (b *boundedOutput) Write(data []byte) (int, error) {
	if int64(len(data)) > MaximumOutputBytes-int64(b.Len()) {
		return 0, ErrLimit
	}
	return b.data.Write(data)
}

func Verify(ctx context.Context, request protocol.ArtifactRequest, files []File, options Options, privateKey, passphrase []byte) (result *Result, resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	defer func() {
		if err := ctx.Err(); err != nil {
			if result != nil {
				clear(result.Output)
			}
			result, resultErr = nil, err
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.Validate() != nil || len(files) == 0 || options.Level != "outer" && options.Level != "private" || options.Export && options.Level != "private" || options.Sensitive && options.Level != "private" || !evidence.ValidAuditRecipientFingerprint(options.Recipient) {
		return nil, ErrInput
	}
	var expected evidence.ProducerId
	if options.Producer != "" {
		if expected.UnmarshalText([]byte(options.Producer)) != nil || expected.IsZero() || expected.String() != options.Producer {
			return nil, ErrInput
		}
	} else if !options.AllowUntrusted {
		return nil, ErrInput
	}
	if len(privateKey) != 0 && (options.Level != "private" || options.Recipient == "") || len(privateKey) == 0 && len(passphrase) != 0 {
		return nil, ErrInput
	}
	var total int64
	seen := make(map[string]bool, len(files))
	for _, file := range files {
		if file.Name == "" || seen[file.Name] || len(file.Data) == 0 {
			return nil, ErrInput
		}
		if int64(len(file.Data)) > MaximumInputBytes-total {
			return nil, ErrLimit
		}
		seen[file.Name] = true
		total += int64(len(file.Data))
	}
	if request.Operation == protocol.DownloadRecording {
		if len(files) != 1 || files[0].Name != "recording" || options.Sensitive || options.AuditScope != "" {
			return nil, ErrInput
		}
		return verifyRecording(ctx, request, files[0].Data, options, expected, privateKey, passphrase)
	}
	if options.AuditScope != "complete" && options.AuditScope != "captured-prefix" {
		return nil, ErrInput
	}
	return verifyAudit(ctx, request, files, options, expected, privateKey, passphrase)
}

func privateIdentities(private, passphrase []byte, expected string) (*keydata.AgeSshIdentities, error) {
	if expected == "" {
		return nil, nil
	}
	parsed, err := browserkey.ParsePrivateKey(private, passphrase)
	if err != nil {
		return nil, ErrKey
	}
	key, err := keydata.PrivateKeyFromSdk(parsed)
	if err != nil || ssh.FingerprintSHA256(key.PublicKey().ToSsh()) != expected {
		return nil, ErrKey
	}
	identities, err := keydata.NewAgeSshIdentities([]keydata.PrivateKey{key})
	if err != nil {
		return nil, ErrKey
	}
	return identities, nil
}

func resultFor(kind string, options Options, producer evidence.ProducerId, trusted bool) *Result {
	trust := "untrusted"
	if trusted {
		trust = "pinned"
	}
	return &Result{Kind: kind, Validation: options.Level, Trust: trust, Producer: producer.String(), ExpectedRecipient: options.Recipient, Decryption: "not-checked", Records: "0", PrivateRecords: "0"}
}

func verificationError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, ErrLimit) {
		return ErrLimit
	}
	return ErrVerification
}

func verifyRecording(ctx context.Context, request protocol.ArtifactRequest, data []byte, options Options, expected evidence.ProducerId, private, passphrase []byte) (*Result, error) {
	// All outer/full/export passes consume this exact owned immutable image.
	data = bytes.Clone(data)
	defer clear(data)
	reader := bytes.NewReader(data)
	if !bytes.HasPrefix(data, []byte(nativeformat.RecordingMagic)) {
		if options.Recipient != "" || len(private) != 0 {
			return nil, ErrInput
		}
		verified, err := cast.VerifyCast(reader, cast.CastVerifyOptions{Context: ctx, MaximumBytes: MaximumInputBytes, ExpectedProducerId: expected, AllowUntrusted: options.AllowUntrusted})
		if err != nil {
			return nil, verificationError(err)
		}
		if verified.Metadata.RecordingId.String() != request.ID {
			return nil, ErrVerification
		}
		result := resultFor("recording", options, verified.Metadata.ProducerId, verified.Trusted)
		result.Validation, result.RecordingID, result.Decryption = "private", request.ID, "not-encrypted"
		if options.Export {
			result.Output, result.OutputFormat = bytes.Clone(data), "cast"
		}
		return result, nil
	}
	verify := cast.NativeRecordingVerifyOptions{Context: ctx, ExpectedProducerId: expected, AllowUntrusted: options.AllowUntrusted, MaximumContainerBytes: MaximumInputBytes, MaximumCastBytes: MaximumOutputBytes}
	outer, err := cast.VerifyNativeRecordingOuter(reader, int64(len(data)), verify)
	if err != nil {
		return nil, verificationError(err)
	}
	if cast.Id(outer.Header.RecordingId).String() != request.ID || outer.Header.Recipient != options.Recipient {
		return nil, ErrVerification
	}
	result := resultFor("recording", options, evidence.ProducerId(outer.Header.ProducerId), outer.Trusted)
	result.RecordingID = request.ID
	if outer.Header.Encryption == 0 {
		result.Decryption = "not-encrypted"
	}
	if options.Level == "outer" {
		return result, nil
	}
	keys, err := privateIdentities(private, passphrase, options.Recipient)
	if err != nil {
		return nil, err
	}
	if options.Export {
		var output boundedOutput
		defer func() { clear(output.Bytes()) }()
		_, err = cast.ExportNativeRecordingCast(reader, int64(len(data)), keys, &output, verify)
		if err == nil {
			result.Output, result.OutputFormat = bytes.Clone(output.Bytes()), "cast"
		}
	} else {
		_, err = cast.VerifyNativeRecordingFull(reader, int64(len(data)), keys, verify)
	}
	if err != nil {
		return nil, verificationError(err)
	}
	if outer.Header.Encryption == 1 {
		result.Decryption = "authenticated"
	}
	return result, nil
}

func verifyAudit(ctx context.Context, request protocol.ArtifactRequest, files []File, options Options, expected evidence.ProducerId, private, passphrase []byte) (*Result, error) {
	var head []byte
	var published []evidence.AuditPublishedSegment
	var active *evidence.AuditActiveSegment
	lastData := make(map[uint64][]byte)
	activeName := "active.baudit"
	if options.Recipient != "" {
		activeName = "active.beaudit"
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if file.Name == "head.cbor" {
			if len(file.Data) > nativeformat.MaxMetadataPayload {
				return nil, ErrInput
			}
			head = bytes.Clone(file.Data)
			continue
		}
		image, err := evidence.NewAuditSegmentImage(file.Data)
		if err != nil {
			return nil, ErrLimit
		}
		if file.Name == activeName {
			active = &evidence.AuditActiveSegment{Image: image}
			continue
		}
		sequence, hash, ok := evidence.ParseAuditSegmentName(file.Name, options.Recipient != "")
		if !ok {
			return nil, ErrInput
		}
		published = append(published, evidence.AuditPublishedSegment{Sequence: sequence, Hash: hash, Image: image})
		lastData[sequence] = file.Data
	}
	sort.Slice(published, func(i, j int) bool { return published[i].Sequence < published[j].Sequence })
	if active != nil && len(published) > 0 {
		last := published[len(published)-1]
		// This attests logical byte equality only, never original OS hardlinks.
		var raw []byte
		for _, file := range files {
			if file.Name == activeName {
				raw = file.Data
				break
			}
		}
		if bytes.Equal(raw, lastData[last.Sequence]) {
			active.AliasOfPublished = last.Sequence
		}
	}
	mode := evidence.AuditProducerComplete
	if options.AuditScope == "captured-prefix" {
		mode = evidence.AuditProducerCapturedPrefix
	}
	verify := evidence.AuditProducerOptions{Auditlog: request.Auditlog, ExpectedProducerId: expected, AllowUntrusted: options.AllowUntrusted, ExpectedEncryptionRecipient: options.Recipient, Mode: mode}
	newSnapshot := func() (*evidence.AuditByteSnapshot, error) {
		return evidence.NewAuditByteSnapshot(head, published, active)
	}
	snapshot, err := newSnapshot()
	if err != nil {
		return nil, ErrInput
	}
	outer, err := evidence.VerifyAuditProducerIntegrity(ctx, snapshot, verify)
	if err != nil {
		return nil, verificationError(err)
	}
	result := resultFor("audit", options, outer.ProducerId, outer.Trusted)
	result.AuditScope, result.Records, result.PrivateRecords = options.AuditScope, strconv.FormatUint(outer.RecordCount, 10), strconv.FormatUint(outer.PrivateRecordCount, 10)
	if options.Recipient == "" {
		result.Decryption = "not-encrypted"
	}
	if options.Level == "outer" {
		return result, nil
	}
	verify.DecryptionIdentities, err = privateIdentities(private, passphrase, options.Recipient)
	if err != nil {
		return nil, err
	}
	verify.WithSensitive = options.Sensitive
	snapshot, err = newSnapshot()
	if err != nil {
		return nil, ErrInput
	}
	var summary evidence.AuditProducerSummary
	if options.Export {
		verified, err := evidence.VerifyAuditProducerSnapshot(ctx, snapshot, verify)
		if err != nil {
			return nil, verificationError(err)
		}
		summary = verified.Summary
		var output boundedOutput
		defer func() { clear(output.Bytes()) }()
		if err := verified.ExportJSONLines(&output, evidence.RecordOrderChain); err != nil {
			return nil, verificationError(err)
		}
		result.Output, result.OutputFormat = bytes.Clone(output.Bytes()), "jsonl"
	} else {
		summary, err = evidence.VerifyAuditProducerIntegrity(ctx, snapshot, verify)
	}
	if err != nil {
		return nil, verificationError(err)
	}
	result.PrivateRecords = strconv.FormatUint(summary.PrivateRecordCount, 10)
	if options.Recipient != "" {
		result.Decryption = "no-private-records"
		if summary.PrivateRecordCount > 0 {
			result.Decryption = "authenticated"
		}
	}
	return result, nil
}

var _ io.Writer = (*boundedOutput)(nil)
