package recording

import (
	"encoding/json"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	castZstdHeadSchema       = "bifroest.session-recording-zstd-head/v1"
	maximumCastZstdHeadBytes = 4096
)

type castZstdHeadWire struct {
	Schema        string                     `json:"schema"`
	FormatVersion uint8                      `json:"formatVersion"`
	RecordingId   Id                         `json:"recordingId"`
	ProducerId    audit.ProducerId           `json:"producerId"`
	ChunkCount    uint64                     `json:"chunkCount"`
	PrefixBytes   uint64                     `json:"prefixBytes"`
	LastUnitHash  audit.SessionRecordingHash `json:"lastUnitHash"`
	Signature     []byte                     `json:"signature"`
}

func encodeCastZstdHead(value audit.SessionRecordingZstdHead) ([]byte, error) {
	payload, err := json.Marshal(castZstdHeadWire{
		Schema:        castZstdHeadSchema,
		FormatVersion: value.FormatVersion,
		RecordingId:   Id(value.RecordingId),
		ProducerId:    value.ProducerId,
		ChunkCount:    value.ChunkCount,
		PrefixBytes:   value.PrefixBytes,
		LastUnitHash:  value.LastUnitHash,
		Signature:     value.Signature,
	})
	if err != nil {
		return nil, errors.System.Newf("cannot encode Cast Zstandard head: %w", err)
	}
	if len(payload) > maximumCastZstdHeadBytes {
		return nil, errors.System.Newf("cast Zstandard head exceeds %d bytes", maximumCastZstdHeadBytes)
	}
	return payload, nil
}

func decodeCastZstdHead(payload []byte) (audit.SessionRecordingZstdHead, error) {
	if len(payload) == 0 || len(payload) > maximumCastZstdHeadBytes {
		return audit.SessionRecordingZstdHead{}, errors.System.Newf("cast Zstandard head size is outside the supported range")
	}
	var wire castZstdHeadWire
	if err := decodeCanonicalCastJSON(payload, &wire); err != nil {
		return audit.SessionRecordingZstdHead{}, errors.System.Newf("illegal Cast Zstandard head: %w", err)
	}
	if wire.Schema != castZstdHeadSchema {
		return audit.SessionRecordingZstdHead{}, errors.System.Newf("unsupported Cast Zstandard head schema %q", wire.Schema)
	}
	return audit.SessionRecordingZstdHead{
		FormatVersion: wire.FormatVersion,
		RecordingId:   uuid.UUID(wire.RecordingId),
		ProducerId:    wire.ProducerId,
		ChunkCount:    wire.ChunkCount,
		PrefixBytes:   wire.PrefixBytes,
		LastUnitHash:  wire.LastUnitHash,
		Signature:     append([]byte(nil), wire.Signature...),
	}, nil
}
