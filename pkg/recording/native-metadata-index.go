package recording

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/metadatacache"
	"github.com/engity-com/bifroest/pkg/recording/cast"
)

func (r *LocalNativeRecordingRepository) indexedMetadata(ctx context.Context, path string, id Id) (summary NativeRecordingSummary, resultErr error) {
	file, err := openSealedLocalFile(path)
	if err != nil {
		return summary, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return summary, err
	}
	stamp, err := metadatacache.Fingerprint(file)
	if err != nil {
		return summary, err
	}
	err = r.metadata.UseFile(ctx, path, stamp, 4<<10, func(output io.Writer) error {
		catalogReadWork(ctx, false)
		format, ok := r.repository.format.(*localNativeRecordingFormat)
		if !ok {
			return fmt.Errorf("native metadata requires native format")
		}
		options := format.options
		options.Context = ctx
		options.ExpectedProducerId = r.repository.identity.ProducerId()
		options.AllowUntrusted = false
		value, err := cast.ReadNativeRecordingMetadata(file, info.Size(), options)
		if err != nil {
			return err
		}
		if Id(value.Header.RecordingId) != id || (value.Header.Encryption == 1) != (format.recipient != nil) {
			return fmt.Errorf("recording metadata identity/encryption mismatch")
		}
		status, err := castStatusFromNativeRecording(value.Seal.Status)
		if err != nil {
			return err
		}
		row := NativeRecordingSummary{RecordingId: id, ProducerId: audit.ProducerId(value.Header.ProducerId), RecipientFingerprint: value.Header.Recipient, Status: status, ChunkCount: value.Seal.ChunkCount, CastBytes: value.Seal.CastBytes, Digest: CastDigest(value.Seal.CastDigest), Bytes: uint64(info.Size())}
		row.StartedAt, _ = value.Header.StartedAt.Time()
		row.EndedAt, _ = value.Seal.EndedAt.Time()
		if value.Metadata != nil {
			row.Flow, row.SessionID, row.User = value.Metadata.Flow.String(), value.Metadata.SessionId.String(), value.Metadata.User
		}
		return json.NewEncoder(output).Encode(row)
	}, func(input io.Reader) error {
		decoder := json.NewDecoder(input)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&summary); err != nil {
			return err
		}
		if decoder.Decode(new(any)) != io.EOF || summary.RecordingId != id {
			return fmt.Errorf("invalid recording metadata index")
		}
		return nil
	})
	if err != nil {
		return NativeRecordingSummary{}, err
	}
	current, err := metadatacache.Fingerprint(file)
	if err != nil {
		return NativeRecordingSummary{}, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || !os.SameFile(info, pathInfo) || current != stamp {
		return NativeRecordingSummary{}, fmt.Errorf("recording changed during metadata selection: %v", err)
	}
	return summary, nil
}
