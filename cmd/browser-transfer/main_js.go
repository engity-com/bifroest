//go:build js && wasm

// Browser-only transport decoding. It receives an already-fetched immutable
// response image, never a bearer, private key, URL, command or filesystem path.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"syscall/js"

	"github.com/engity-com/bifroest/pkg/management/client"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/management/wire"
)

const maximumBufferedBytes int64 = 64 << 20
const maximumResponseImageBytes = 72 << 20

type file struct {
	name string
	data bytes.Buffer
	size int64
}

func (f *file) Write(data []byte) (int, error) {
	if int64(len(data)) > f.size-int64(f.data.Len()) {
		return 0, wire.ErrArtifactLimit
	}
	return f.data.Write(data)
}

func (f *file) Close() error { return nil }

type auditSink struct {
	files []*file
}

func (s *auditSink) Begin(header wire.AuditSnapshotHeader) error {
	var total int64
	for _, entry := range header.Files {
		if entry.Size > maximumBufferedBytes-total {
			return wire.ErrArtifactLimit
		}
		total += entry.Size
	}
	return nil
}

func (s *auditSink) Open(entry wire.AuditSnapshotEntry) (io.WriteCloser, error) {
	f := &file{name: entry.Name, size: entry.Size}
	s.files = append(s.files, f)
	return f, nil
}

var attempted bool

func receive(_ js.Value, args []js.Value) (result any) {
	result = map[string]any{"ok": false}
	defer func() {
		if recover() != nil {
			result = map[string]any{"ok": false}
		}
	}()
	if attempted {
		return result
	}
	attempted = true
	if len(args) != 6 {
		return result
	}
	for _, index := range []int{0, 1, 2, 4} {
		if args[index].Type() != js.TypeString {
			return result
		}
	}
	if args[5].Type() != js.TypeNumber || args[5].Int() != http.StatusOK || !args[3].InstanceOf(js.Global().Get("Uint8Array")) {
		return result
	}
	length := args[3].Get("byteLength").Int()
	if length < 1 || length > maximumResponseImageBytes {
		return result
	}
	request := protocol.ArtifactRequest{Auditlog: args[1].String(), ID: args[2].String()}
	switch args[0].String() {
	case "recording":
		request.Operation = protocol.DownloadRecording
	case "audit":
		request.Operation = protocol.DownloadAudit
	default:
		return result
	}
	if request.Validate() != nil {
		return result
	}
	data := make([]byte, length)
	defer clear(data)
	if js.CopyBytesToGo(data, args[3]) != length {
		return result
	}
	response, err := client.NewHTTPTransferResponse(&http.Response{
		StatusCode: args[5].Int(), Header: http.Header{"Content-Type": []string{args[4].String()}},
		Body: io.NopCloser(bytes.NewReader(data)),
	}, request)
	if err != nil {
		return result
	}
	var files []*file
	defer func() {
		for _, f := range files {
			clear(f.data.Bytes())
		}
	}()
	var metadata any
	if request.Operation == protocol.DownloadRecording {
		f := &file{name: "recording", size: maximumBufferedBytes}
		files = []*file{f}
		metadata, err = client.ReadRecording(context.Background(), response, request.ID, f, maximumBufferedBytes)
	} else {
		sink := &auditSink{}
		metadata, err = client.ReadAuditSnapshot(context.Background(), response, request.Auditlog, sink)
		files = sink.files
	}
	if err != nil {
		if errors.Is(err, wire.ErrArtifactLimit) {
			return map[string]any{"ok": false, "code": "too-large"}
		}
		return result
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return result
	}
	output := make([]any, 0, len(files))
	for _, f := range files {
		buffer := js.Global().Get("Uint8Array").New(f.data.Len())
		if js.CopyBytesToJS(buffer, f.data.Bytes()) != f.data.Len() {
			return result
		}
		output = append(output, map[string]any{"name": f.name, "data": buffer})
	}
	return map[string]any{"ok": true, "metadata": string(encoded), "files": output}
}

func main() {
	js.Global().Set("bifroestTransferReceive", js.FuncOf(receive))
	js.Global().Call("postMessage", map[string]any{"kind": "ready"})
	select {}
}
