package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/management/wire"
)

type transferTestBody struct {
	io.Reader
	closes   atomic.Int32
	closeErr error
}

func (this *transferTestBody) Close() error { this.closes.Add(1); return this.closeErr }

func transferFixture(t *testing.T, data []byte, complete bool) []byte {
	t.Helper()
	var out bytes.Buffer
	writer, err := wire.NewTransferWriter(&out, protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "default"})
	require.NoError(t, err)
	_, err = writer.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.EndData())
	if complete {
		require.NoError(t, writer.Complete())
	}
	return out.Bytes()
}

func TestTransferResponseDataEndIsNotTaskSuccess(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "default"}
	data := bytes.Repeat([]byte("a"), wire.MaximumTransferFrameBytes+17)
	for _, complete := range []bool{false, true} {
		body := &transferTestBody{Reader: bytes.NewReader(transferFixture(t, data, complete))}
		response, err := NewTransferResponse(body, request)
		require.NoError(t, err)
		provisional, err := io.ReadAll(response)
		require.NoError(t, err)
		require.Equal(t, data, provisional)
		err = response.Complete()
		if complete {
			require.NoError(t, err)
		} else {
			require.ErrorContains(t, err, "completion is missing")
		}
		require.NoError(t, response.Close())
		require.NoError(t, response.Abort())
		require.EqualValues(t, 1, body.closes.Load())
	}
	body := &transferTestBody{Reader: bytes.NewReader(transferFixture(t, data, false))}
	response, err := NewTransferResponse(body, request)
	require.NoError(t, err)
	result, err := ReadBytes(t.Context(), response, int64(len(data)))
	require.Error(t, err)
	require.Nil(t, result, "data/end/EOF alone must not produce a successful result")
}

func TestTransferResponseRejectsBadFramesAndTruncation(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "default"}
	valid := transferFixture(t, []byte("payload"), true)
	dataEnd := transferFixture(t, []byte("payload"), false)
	for _, raw := range [][]byte{nil, []byte("wrong magic"), valid[:len(wire.TransferMagic)+3], dataEnd[:len(dataEnd)-1], append(bytes.Clone(valid), 1), append(bytes.Clone(valid), valid...)} {
		response, err := NewTransferResponse(&transferTestBody{Reader: bytes.NewReader(raw)}, request)
		require.NoError(t, err)
		result, err := ReadBytes(t.Context(), response, 4096)
		require.Error(t, err)
		require.Nil(t, result)
	}
	for _, header := range []struct {
		kind byte
		size uint32
	}{{wire.TransferData, 0}, {wire.TransferData, wire.MaximumTransferFrameBytes + 1}, {wire.TransferDataEnd, 1}, {wire.TransferComplete, 1}, {99, 0}} {
		raw := []byte(wire.TransferMagic)
		raw = append(raw, header.kind, 0, 0, 0, 0)
		binary.BigEndian.PutUint32(raw[len(raw)-4:], header.size)
		response, err := NewTransferResponse(&transferTestBody{Reader: bytes.NewReader(raw)}, request)
		require.NoError(t, err)
		_, err = ReadBytes(t.Context(), response, 4096)
		require.Error(t, err)
	}
}

func TestTransferCompletionPinsRequestCountDigestAndCanonicalEnvelope(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "default"}
	prefix := transferFixture(t, []byte("payload"), false)
	full := transferFixture(t, []byte("payload"), true)
	headerOffset := len(prefix)
	size := binary.BigEndian.Uint32(full[headerOffset+1 : headerOffset+5])
	var original wire.TransferCompletion
	require.NoError(t, cbor.Unmarshal(full[headerOffset+5:headerOffset+5+int(size)], &original))
	for _, change := range []func(*wire.TransferCompletion){func(v *wire.TransferCompletion) { v.Version++ }, func(v *wire.TransferCompletion) { v.Bytes++ }, func(v *wire.TransferCompletion) { v.SHA256[0] ^= 1 }, func(v *wire.TransferCompletion) { v.Request.Auditlog = "other" }, func(v *wire.TransferCompletion) { v.Request.Operation = protocol.DownloadRecording }} {
		value := original
		change(&value)
		encoded, err := cbor.Marshal(value)
		require.NoError(t, err)
		raw := append(bytes.Clone(prefix), wire.TransferComplete, 0, 0, 0, 0)
		binary.BigEndian.PutUint32(raw[len(raw)-4:], uint32(len(encoded)))
		raw = append(raw, encoded...)
		response, err := NewTransferResponse(&transferTestBody{Reader: bytes.NewReader(raw)}, request)
		require.NoError(t, err)
		result, err := ReadBytes(t.Context(), response, 4096)
		require.Error(t, err)
		require.Nil(t, result)
	}
	encoded, err := cbor.Marshal(original)
	require.NoError(t, err)
	require.Equal(t, byte(0xa4), encoded[0])
	encoded[0] = 0xa5
	encoded = append(encoded, 1, 1)
	raw := append(bytes.Clone(prefix), wire.TransferComplete, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(raw[len(raw)-4:], uint32(len(encoded)))
	raw = append(raw, encoded...)
	response, err := NewTransferResponse(&transferTestBody{Reader: bytes.NewReader(raw)}, request)
	require.NoError(t, err)
	_, err = ReadBytes(t.Context(), response, 4096)
	require.Error(t, err)
}

func TestTransferResponseCancellationClosesBlockedBody(t *testing.T) {
	for _, phase := range []string{"magic", "completion"} {
		t.Run(phase, func(t *testing.T) {
			reader, writer := io.Pipe()
			defer writer.Close()
			request := protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "default"}
			response, err := NewTransferResponse(reader, request)
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			results := make(chan received[[]byte], 1)
			go func() { value, err := ReadBytes(ctx, response, 4096); results <- received[[]byte]{value, err} }()
			if phase == "completion" {
				_, err := writer.Write(transferFixture(t, []byte("provisional"), false))
				require.NoError(t, err)
			}
			cancel()
			result := await(t, results)
			require.ErrorIs(t, result.err, context.Canceled)
			require.Nil(t, result.value)
		})
	}
}

func TestHTTPTransferResponseFailsClosedAndOwnsBody(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "default"}
	for _, change := range []func(*http.Response){func(v *http.Response) { v.StatusCode = 403 }, func(v *http.Response) { v.Header.Set("Content-Type", "application/json") }, func(v *http.Response) { v.Header.Add("Content-Type", wire.TransferMediaType) }, func(v *http.Response) { v.Header.Set("Content-Encoding", "gzip") }, func(v *http.Response) { v.Uncompressed = true }} {
		body := &transferTestBody{Reader: bytes.NewReader(nil)}
		raw := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {wire.TransferMediaType}}, Body: body}
		change(raw)
		_, err := NewHTTPTransferResponse(raw, request)
		require.Error(t, err)
		require.EqualValues(t, 1, body.closes.Load())
	}
	failure := errors.New("close failed")
	body := &transferTestBody{Reader: bytes.NewReader(transferFixture(t, []byte("payload"), true)), closeErr: failure}
	response, err := NewHTTPTransferResponse(&http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {wire.TransferMediaType}}, Body: body}, request)
	require.NoError(t, err)
	result, err := ReadBytes(t.Context(), response, 4096)
	require.ErrorIs(t, err, failure)
	require.Nil(t, result)
	require.EqualValues(t, 1, body.closes.Load())
}

func TestTransferResponseRejectsPrematureCompletionBoundsAndExtraPhases(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "default"}
	prefix := transferFixture(t, []byte("payload"), false)
	for _, frame := range []struct {
		kind byte
		size uint32
	}{{wire.TransferComplete, 0}, {wire.TransferComplete, wire.MaximumTransferCompletionBytes + 1}, {wire.TransferData, 1}, {wire.TransferDataEnd, 0}, {255, 0}} {
		raw := append(bytes.Clone(prefix), frame.kind, 0, 0, 0, 0)
		binary.BigEndian.PutUint32(raw[len(raw)-4:], frame.size)
		response, err := NewTransferResponse(&transferTestBody{Reader: bytes.NewReader(raw)}, request)
		require.NoError(t, err)
		result, err := ReadBytes(t.Context(), response, 4096)
		require.Error(t, err)
		require.Nil(t, result)
	}
	response, err := NewTransferResponse(&transferTestBody{Reader: bytes.NewReader(transferFixture(t, []byte("payload"), true))}, request)
	require.NoError(t, err)
	require.Error(t, response.Complete(), "cannot skip unread artifact data")
	require.NoError(t, response.Close())
	response, err = NewTransferResponse(&transferTestBody{Reader: bytes.NewReader(transferFixture(t, []byte("payload"), true))}, request)
	require.NoError(t, err)
	_, err = io.ReadAll(response)
	require.NoError(t, err)
	require.NoError(t, response.Complete())
	require.Error(t, response.Complete(), "completion cannot be replayed")
	require.NoError(t, response.Close())
	response, err = NewTransferResponse(&transferTestBody{Reader: bytes.NewReader([]byte{wire.TransferData, 0, 0, 0, 1, 'x'})}, request)
	require.NoError(t, err)
	response.started = true
	response.count = uint64(wire.MaximumTransferBytes(request))
	_, err = response.Read(make([]byte, 1))
	require.Error(t, err)
	require.NoError(t, response.Close())
}

func TestTransferResponseRequiresPhysicalEOFAndPreservesPostCompletionFailure(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "default"}
	failure := errors.New("HTTP body failed after completion bytes")
	body := &transferTestBody{Reader: io.MultiReader(bytes.NewReader(transferFixture(t, []byte("payload"), true)), transferErrorReaderForClient{failure})}
	response, err := NewTransferResponse(body, request)
	require.NoError(t, err)
	result, err := ReadBytes(t.Context(), response, 4096)
	require.Error(t, err)
	require.ErrorContains(t, err, failure.Error())
	require.Nil(t, result)
	require.EqualValues(t, 1, body.closes.Load())
}

type transferErrorReaderForClient struct{ err error }

func (this transferErrorReaderForClient) Read([]byte) (int, error) { return 0, this.err }
