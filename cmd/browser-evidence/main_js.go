//go:build js && wasm

// This isolated tab-local bridge has no bearer, URL, command or server action.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/engity-com/bifroest/pkg/uuidtext"
	"io"
	"net/http"
	"syscall/js"

	"github.com/engity-com/bifroest/pkg/browserevidence"
	"github.com/engity-com/bifroest/pkg/browserkey"
	managementclient "github.com/engity-com/bifroest/pkg/management/client"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/management/wire"
	"github.com/engity-com/bifroest/pkg/recording/cast"
)

var used bool
var batchSource string
var recordingBoundID string

func binary(value js.Value, maximum int) []byte {
	if !value.InstanceOf(js.Global().Get("Uint8Array")) {
		panic("invalid buffer")
	}
	length := value.Get("byteLength").Int()
	if length < 0 || length > maximum {
		panic("invalid buffer size")
	}
	result := make([]byte, length)
	if js.CopyBytesToGo(result, value) != length {
		panic("incomplete buffer")
	}
	return result
}

func failure(code string) any { return map[string]any{"ok": false, "code": code} }

func verify(_ js.Value, args []js.Value) any      { return verifyEvidence(args, false) }
func verifyBatch(_ js.Value, args []js.Value) any { return verifyEvidence(args, true) }
func beginBatch(_ js.Value, args []js.Value) any {
	if used || batchSource != "" || len(args) != 1 || args[0].Type() != js.TypeString || !protocol.ValidAuditlogName(args[0].String()) {
		return false
	}
	batchSource = args[0].String()
	return true
}
func beginRecording(_ js.Value, args []js.Value) any {
	if used || batchSource != "" || len(args) != 2 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeString || !protocol.ValidAuditlogName(args[0].String()) || !protocol.ValidID(args[1].String()) {
		return false
	}
	batchSource, recordingBoundID = args[0].String(), args[1].String()
	return true
}

type sourceRecordingSink struct{ data bytes.Buffer }

func (s *sourceRecordingSink) Write(data []byte) (int, error) {
	if int64(len(data)) > browserevidence.MaximumInputBytes-int64(s.data.Len()) {
		return 0, wire.ErrArtifactLimit
	}
	return s.data.Write(data)
}
func (*sourceRecordingSink) Close() error { return nil }

// No credential or URL enters this receiver. Every file is a separate native
// transfer response with its own completion and raw EOF, never a concatenation
// interpreted as optimistic success. Runtime reuse retains no file state.
func receiveSource(_ js.Value, args []js.Value) (result any) {
	result = failure("input")
	defer func() {
		if recover() != nil {
			result = failure("input")
		}
	}()
	if used || batchSource == "" || recordingBoundID != "" || len(args) != 5 || args[0].Type() != js.TypeString || args[0].String() != batchSource || args[1].Type() != js.TypeString || args[3].Type() != js.TypeString || args[3].String() != wire.TransferMediaType || args[4].Type() != js.TypeNumber || args[4].Int() != 200 {
		return result
	}
	request := protocol.ArtifactRequest{Operation: protocol.DownloadRecording, Auditlog: batchSource, ID: args[1].String()}
	if request.Validate() != nil {
		return result
	}
	used = true
	defer func() { used = false }()
	data := binary(args[2], 72<<20)
	defer clear(data)
	response, err := managementclient.NewHTTPTransferResponse(&http.Response{StatusCode: args[4].Int(), Header: http.Header{"Content-Type": []string{args[3].String()}}, Body: io.NopCloser(bytes.NewReader(data))}, request)
	if err != nil {
		return result
	}
	sink := &sourceRecordingSink{}
	defer func() { clear(sink.data.Bytes()) }()
	metadata, err := managementclient.ReadRecording(context.Background(), response, request.ID, sink, browserevidence.MaximumInputBytes)
	if err != nil {
		if errors.Is(err, wire.ErrArtifactLimit) {
			return failure("limit")
		}
		return result
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return result
	}
	output := js.Global().Get("Uint8Array").New(sink.data.Len())
	if js.CopyBytesToJS(output, sink.data.Bytes()) != sink.data.Len() {
		return result
	}
	return map[string]any{"ok": true, "metadata": string(encoded), "files": []any{map[string]any{"name": "recording", "data": output}}}
}

func verifyEvidence(args []js.Value, batch bool) (result any) {
	result = failure("verification")
	defer func() {
		if recover() != nil {
			result = failure("verification")
		}
	}()
	if used || batch && batchSource == "" || !batch && batchSource != "" {
		return result
	}
	used = true
	if batch {
		defer func() { used = false }()
	}
	if len(args) != 7 && len(args) != 8 || len(args) == 8 && args[7].Type() != js.TypeFunction {
		return failure("input")
	}
	for _, index := range []int{0, 1, 2, 3} {
		if args[index].Type() != js.TypeString {
			return failure("input")
		}
	}
	request := protocol.ArtifactRequest{Auditlog: args[1].String(), ID: args[2].String()}
	switch args[0].String() {
	case "recording":
		request.Operation = protocol.DownloadRecording
	case "audit":
		request.Operation = protocol.DownloadAudit
	default:
		return failure("input")
	}
	if request.Validate() != nil {
		return failure("input")
	}
	optionsJSON := []byte(args[3].String())
	if len(optionsJSON) > 8192 || cast.RejectDuplicateJSONFields(optionsJSON) != nil {
		return failure("input")
	}
	var options browserevidence.Options
	decoder := json.NewDecoder(bytes.NewReader(optionsJSON))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&options) != nil || decoder.Decode(new(any)) != io.EOF {
		return failure("input")
	}
	// A batch owns one source and can return verification metadata only. Each
	// call still copies, independently verifies and clears its complete input.
	if batch && (request.Operation != protocol.DownloadRecording || request.Auditlog != batchSource || (recordingBoundID != "" && request.ID != recordingBoundID) || (recordingBoundID == "" && options.Export) || options.Sensitive || options.AuditScope != "") {
		return failure("input")
	}
	if len(args) == 8 {
		options.Progress = func(phase string, completed, total int64) error { args[7].Invoke(phase, completed, total); return nil }
	}
	if !args[4].InstanceOf(js.Global().Get("Array")) || args[4].Length() < 1 || args[4].Length() > 65536 {
		return failure("input")
	}
	var files []browserevidence.File
	defer func() {
		for _, file := range files {
			clear(file.Data)
		}
	}()
	var total int64
	for index := 0; index < args[4].Length(); index++ {
		file := args[4].Index(index)
		if file.Get("name").Type() != js.TypeString || len(file.Get("name").String()) > 255 {
			return failure("input")
		}
		data := binary(file.Get("data"), int(browserevidence.MaximumInputBytes-total))
		total += int64(len(data))
		files = append(files, browserevidence.File{Name: file.Get("name").String(), Data: data})
	}
	private := binary(args[5], browserkey.MaxPrivateKeyBytes)
	defer clear(private)
	password := binary(args[6], browserkey.MaxPassphraseBytes)
	defer clear(password)
	verified, err := browserevidence.Verify(context.Background(), request, files, options, private, password)
	if err != nil {
		switch {
		case errors.Is(err, browserevidence.ErrInput):
			return failure("input")
		case errors.Is(err, browserevidence.ErrKey):
			return failure("key")
		case errors.Is(err, browserevidence.ErrLimit):
			return failure("limit")
		default:
			return result
		}
	}
	defer clear(verified.Output)
	metadata, err := json.Marshal(verified)
	if err != nil {
		return result
	}
	output := js.Global().Get("Uint8Array").New(len(verified.Output))
	if js.CopyBytesToJS(output, verified.Output) != len(verified.Output) {
		return result
	}
	return map[string]any{"ok": true, "metadata": string(metadata), "output": output}
}

func playback(_ js.Value, args []js.Value) (result any) {
	result = failure("verification")
	defer func() {
		if recover() != nil {
			result = failure("verification")
		}
	}()
	if used || batchSource != "" {
		return result
	}
	used = true
	if len(args) != 4 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeString || args[2].Type() != js.TypeBoolean || !protocol.ValidID(args[0].String()) || len(args[1].String()) > 64 {
		return failure("input")
	}
	image := binary(args[3], int(browserevidence.MaximumInputBytes))
	defer clear(image)
	prepared, err := browserevidence.PreparePlayback(context.Background(), image, args[0].String(), args[1].String(), args[2].Bool())
	if err != nil {
		if errors.Is(err, browserevidence.ErrInput) {
			return failure("input")
		}
		if errors.Is(err, browserevidence.ErrLimit) {
			return failure("limit")
		}
		return result
	}
	defer clear(prepared.Frames)
	metadata, err := json.Marshal(prepared.Metadata)
	if err != nil {
		return result
	}
	output := js.Global().Get("Uint8Array").New(len(prepared.Frames))
	if js.CopyBytesToJS(output, prepared.Frames) != len(prepared.Frames) {
		return result
	}
	return map[string]any{"ok": true, "metadata": string(metadata), "output": output}
}

func openPlayback(_ js.Value, args []js.Value) (result any) {
	result = failure("input")
	defer func() {
		if recover() != nil {
			result = failure("input")
		}
	}()
	if used || (batchSource != "" && recordingBoundID == "") || len(args) != 4 || args[0].Type() != js.TypeString || !protocol.ValidID(args[0].String()) || (recordingBoundID != "" && !uuidtext.Equal(args[0].String(), recordingBoundID)) {
		return result
	}
	used = true
	if recordingBoundID != "" {
		defer func() { used = false }()
	}
	data := binary(args[1], int(browserevidence.MaximumInputBytes))
	defer clear(data)
	private := binary(args[2], browserkey.MaxPrivateKeyBytes)
	defer clear(private)
	password := binary(args[3], browserkey.MaxPassphraseBytes)
	defer clear(password)
	opened, err := browserevidence.OpenPlayback(context.Background(), data, args[0].String(), private, password)
	if err != nil {
		if errors.Is(err, browserevidence.ErrKey) {
			return failure("key")
		}
		if errors.Is(err, browserevidence.ErrLimit) {
			return failure("limit")
		}
		return result
	}
	defer clear(opened.Frames)
	metadata, err := json.Marshal(opened)
	if err != nil {
		return result
	}
	output := js.Global().Get("Uint8Array").New(len(opened.Frames))
	if js.CopyBytesToJS(output, opened.Frames) != len(opened.Frames) {
		return result
	}
	return map[string]any{"ok": true, "metadata": string(metadata), "output": output}
}

func main() {
	js.Global().Set("bifroestEvidenceVerify", js.FuncOf(verify))
	js.Global().Set("bifroestEvidenceVerifyBatch", js.FuncOf(verifyBatch))
	js.Global().Set("bifroestEvidenceBeginBatch", js.FuncOf(beginBatch))
	js.Global().Set("bifroestRecordingBegin", js.FuncOf(beginRecording))
	js.Global().Set("bifroestRecordingSourceReceive", js.FuncOf(receiveSource))
	js.Global().Set("bifroestEvidencePlayback", js.FuncOf(playback))
	js.Global().Set("bifroestRecordingOpen", js.FuncOf(openPlayback))
	js.Global().Call("postMessage", map[string]any{"kind": "ready"})
	select {}
}
