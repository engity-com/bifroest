//go:build js && wasm

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"syscall/js"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/management/wire"
)

const transferTestID = "34e34ab8-7457-4d88-a5e4-c57791775c3a"

func testTransferImage(t *testing.T, request protocol.ArtifactRequest, payload []byte, complete bool) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := wire.NewTransferWriter(&output, request)
	require.NoError(t, err)
	_, err = writer.Write(payload)
	require.NoError(t, err)
	require.NoError(t, writer.EndData())
	if complete {
		require.NoError(t, writer.Complete())
	}
	return bytes.Clone(output.Bytes())
}

func testReceive(t *testing.T, kind, auditlog, id, media string, image []byte) map[string]any {
	t.Helper()
	input := js.Global().Get("Uint8Array").New(len(image))
	require.Equal(t, len(image), js.CopyBytesToJS(input, image))
	result := receive(js.Undefined(), []js.Value{js.ValueOf(kind), js.ValueOf(auditlog), js.ValueOf(id), input, js.ValueOf(media), js.ValueOf(200)})
	value, ok := result.(map[string]any)
	require.True(t, ok)
	return value
}

func TestBrowserTransferBridgeUsesSharedCompletionAndRejectsSelectorAndEOFFailures(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadRecording, Auditlog: "default", ID: transferTestID}
	content := []byte("opaque bytes; transport completion is not evidence verification")
	var payload bytes.Buffer
	require.NoError(t, wire.WriteRecordingArtifact(&payload, wire.RecordingArtifactHeader{
		Version: 1, ID: transferTestID, ProducerID: fmt.Sprintf("%x", sha256.Sum256([]byte("declared producer"))),
		Size: int64(len(content)), SHA256: fmt.Sprintf("%x", sha256.Sum256(content)),
	}, bytes.NewReader(content)))
	valid := testTransferImage(t, request, payload.Bytes(), true)
	for _, scenario := range []string{"success", "data-end only", "truncated", "trailing", "selector", "media"} {
		attempted = false
		image, id, media := bytes.Clone(valid), transferTestID, wire.TransferMediaType
		switch scenario {
		case "data-end only":
			image = testTransferImage(t, request, payload.Bytes(), false)
		case "truncated":
			image = image[:len(image)-1]
		case "trailing":
			image = append(image, 0)
		case "selector":
			id = "6d05798f-b877-4191-8aa0-4576a30411ad"
		case "media":
			media = "application/octet-stream"
		}
		result := testReceive(t, "recording", "default", id, media, image)
		if scenario == "success" {
			require.Equal(t, true, result["ok"])
			var header wire.RecordingArtifactHeader
			require.NoError(t, json.Unmarshal([]byte(result["metadata"].(string)), &header))
			require.Equal(t, transferTestID, header.ID)
			files := result["files"].([]any)
			require.Len(t, files, 1)
			stored := files[0].(map[string]any)["data"].(js.Value)
			copied := make([]byte, stored.Get("byteLength").Int())
			require.Equal(t, len(copied), js.CopyBytesToGo(copied, stored))
			require.Equal(t, content, copied)
		} else {
			require.Equal(t, map[string]any{"ok": false}, result, scenario)
		}
		require.Equal(t, map[string]any{"ok": false}, testReceive(t, "recording", "default", transferTestID, wire.TransferMediaType, valid), "one worker must never consume a second response")
	}
}

func TestBrowserTransferBridgeLimitsBeforeAllocatingPayloadAndNeverPublishesPartialFiles(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadRecording, Auditlog: "default", ID: transferTestID}
	var payload bytes.Buffer
	// Deliberately oversized declaration with no payload: the limit must win
	// before io.CopyN or any large allocation, not become an EOF/success result.
	require.Error(t, wire.WriteRecordingArtifact(&payload, wire.RecordingArtifactHeader{
		Version: 1, ID: transferTestID, ProducerID: "declared producer", Size: maximumBufferedBytes + 1, SHA256: fmt.Sprintf("%x", sha256.Sum256(nil)),
	}, bytes.NewReader(nil)))
	attempted = false
	result := testReceive(t, "recording", "default", transferTestID, wire.TransferMediaType, testTransferImage(t, request, payload.Bytes(), true))
	require.Equal(t, map[string]any{"ok": false, "code": "too-large"}, result)
	request = protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "default"}
	payload.Reset()
	header := wire.AuditSnapshotHeader{Version: 1, Name: "default", Producer: fmt.Sprintf("%x", sha256.Sum256([]byte("producer")))}
	for index := range 5 {
		header.Files = append(header.Files, wire.AuditSnapshotEntry{Name: fmt.Sprintf("segment-%d.baudit", index), Size: 17 << 20, SHA256: fmt.Sprintf("%x", sha256.Sum256(nil))})
	}
	header.Files = append(header.Files, wire.AuditSnapshotEntry{Name: "head.cbor", Size: 1, SHA256: fmt.Sprintf("%x", sha256.Sum256(nil))})
	require.NoError(t, wire.WriteAuditSnapshotHeader(&payload, header))
	attempted = false
	result = testReceive(t, "audit", "default", "", wire.TransferMediaType, testTransferImage(t, request, payload.Bytes(), true))
	require.Equal(t, map[string]any{"ok": false, "code": "too-large"}, result)
}
