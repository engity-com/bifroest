package client

import (
	"context"
	"fmt"
	"io"
	"math"

	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/management/wire"
)

func ReadBytes(ctx context.Context, response Response, maximum int64) ([]byte, error) {
	return Receive(ctx, response, func(input io.Reader) ([]byte, error) {
		if maximum < 0 || maximum == math.MaxInt64 {
			return nil, fmt.Errorf("invalid management response bound")
		}
		content, err := io.ReadAll(io.LimitReader(input, maximum+1))
		if err != nil {
			return nil, err
		}
		if int64(len(content)) > maximum {
			return nil, fmt.Errorf("management response exceeds %d bytes", maximum)
		}
		return content, nil
	})
}

// ReadWireResult returns a typed legacy CBOR result only after transport success.
// It does not make CLI arguments a browser protocol. A fixed typed HTTP adapter
// can use Receive with its own bounded structured decoder instead.
func ReadWireResult[T any](ctx context.Context, response Response) (T, error) {
	return Receive(ctx, response, func(input io.Reader) (T, error) {
		var result T
		err := wire.DecodeWireResult(input, &result)
		return result, err
	})
}

func ReadRecordingList(ctx context.Context, response Response, consume func(protocol.RecordingView) error) error {
	_, err := Receive(ctx, response, func(input io.Reader) (struct{}, error) {
		if consume == nil {
			return struct{}{}, fmt.Errorf("missing recording consumer")
		}
		return struct{}{}, wire.DecodeRecordingListStream(input, consume)
	})
	return err
}

// ReadRecording and ReadAuditSnapshot write provisional data only. Expected
// selectors are checked as part of decoding, before successful completion can be
// returned. Header producer/recipient/digest assertions are NOT trust anchors.
func ReadRecording(ctx context.Context, response Response, expectedID string, output io.Writer, maximum int64) (wire.RecordingArtifactHeader, error) {
	return Receive(ctx, response, func(input io.Reader) (wire.RecordingArtifactHeader, error) {
		if expectedID == "" || output == nil {
			return wire.RecordingArtifactHeader{}, fmt.Errorf("missing recording selector or sink")
		}
		header, err := wire.ReadRecordingArtifact(input, output, maximum)
		if err == nil && header.ID != expectedID {
			err = fmt.Errorf("remote recording does not match requested ID")
		}
		return header, err
	})
}

func ReadAuditSnapshot(ctx context.Context, response Response, expectedName string, sink wire.AuditSnapshotSink) (wire.AuditSnapshotHeader, error) {
	return Receive(ctx, response, func(input io.Reader) (wire.AuditSnapshotHeader, error) {
		if expectedName == "" {
			return wire.AuditSnapshotHeader{}, fmt.Errorf("missing auditlog selector")
		}
		header, err := wire.ReadAuditSnapshot(input, sink)
		if err == nil && header.Name != expectedName {
			err = fmt.Errorf("remote audit snapshot has the wrong auditlog name")
		}
		return header, err
	})
}
