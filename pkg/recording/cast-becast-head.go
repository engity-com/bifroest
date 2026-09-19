package recording

import (
	"encoding/json"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	castBECastHeadSchema       = "bifroest.session-recording-becast-head/v1"
	maximumCastBECastHeadBytes = 4096
)

type castBECastHeadWire struct {
	Schema               string                     `json:"schema"`
	FormatVersion        uint8                      `json:"formatVersion"`
	CastState            uint8                      `json:"castState"`
	RecordingId          Id                         `json:"recordingId"`
	ProducerId           audit.ProducerId           `json:"producerId"`
	StartedAtUnixSeconds int64                      `json:"startedAtUnixSeconds"`
	StartedAtNanoseconds uint32                     `json:"startedAtNanoseconds"`
	ChunkCount           uint64                     `json:"chunkCount"`
	PrefixBytes          uint64                     `json:"prefixBytes"`
	LastUnitHash         audit.SessionRecordingHash `json:"lastUnitHash"`
	ContentHashState     audit.SessionRecordingHash `json:"contentHashState"`
	ContentHashBytes     uint64                     `json:"contentHashBytes"`
	Signature            []byte                     `json:"signature"`
}

func encodeBECastHead(value audit.SessionRecordingBECastHead) ([]byte, error) {
	payload, err := json.Marshal(castBECastHeadWire{
		Schema:               castBECastHeadSchema,
		FormatVersion:        value.FormatVersion,
		CastState:            value.CastState,
		RecordingId:          Id(value.RecordingId),
		ProducerId:           value.ProducerId,
		StartedAtUnixSeconds: value.StartedAtUnixSeconds,
		StartedAtNanoseconds: value.StartedAtNanoseconds,
		ChunkCount:           value.ChunkCount,
		PrefixBytes:          value.PrefixBytes,
		LastUnitHash:         value.LastUnitHash,
		ContentHashState:     value.ContentHashState,
		ContentHashBytes:     value.ContentHashBytes,
		Signature:            value.Signature,
	})
	if err != nil {
		return nil, errors.System.Newf("cannot encode BECast head: %w", err)
	}
	if len(payload) > maximumCastBECastHeadBytes {
		return nil, errors.System.Newf("BECast head exceeds %d bytes", maximumCastBECastHeadBytes)
	}
	return payload, nil
}

func decodeBECastHead(payload []byte) (audit.SessionRecordingBECastHead, error) {
	if len(payload) == 0 || len(payload) > maximumCastBECastHeadBytes {
		return audit.SessionRecordingBECastHead{}, errors.System.Newf("BECast head size is outside the supported range")
	}
	var wire castBECastHeadWire
	if err := decodeCanonicalCastJSON(payload, &wire); err != nil {
		return audit.SessionRecordingBECastHead{}, errors.System.Newf("illegal BECast head: %w", err)
	}
	if wire.Schema != castBECastHeadSchema {
		return audit.SessionRecordingBECastHead{}, errors.System.Newf("unsupported BECast head schema %q", wire.Schema)
	}
	return audit.SessionRecordingBECastHead{
		FormatVersion:        wire.FormatVersion,
		CastState:            wire.CastState,
		RecordingId:          uuid.UUID(wire.RecordingId),
		ProducerId:           wire.ProducerId,
		StartedAtUnixSeconds: wire.StartedAtUnixSeconds,
		StartedAtNanoseconds: wire.StartedAtNanoseconds,
		ChunkCount:           wire.ChunkCount,
		PrefixBytes:          wire.PrefixBytes,
		LastUnitHash:         wire.LastUnitHash,
		ContentHashState:     wire.ContentHashState,
		ContentHashBytes:     wire.ContentHashBytes,
		Signature:            append([]byte(nil), wire.Signature...),
	}, nil
}
