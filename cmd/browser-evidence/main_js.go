//go:build js && wasm

// This isolated tab-local bridge has no bearer, URL, command or server action.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"syscall/js"

	"github.com/engity-com/bifroest/pkg/browserevidence"
	"github.com/engity-com/bifroest/pkg/browserkey"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/recording/cast"
)

var used bool

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

func verify(_ js.Value, args []js.Value) (result any) {
	result = failure("verification")
	defer func() {
		if recover() != nil {
			result = failure("verification")
		}
	}()
	if used {
		return result
	}
	used = true
	if len(args) != 7 {
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
	if used {
		return result
	}
	used = true
	if len(args) != 4 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeString || args[2].Type() != js.TypeBoolean || len(args[0].String()) != 36 || len(args[1].String()) > 64 {
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

func main() {
	js.Global().Set("bifroestEvidenceVerify", js.FuncOf(verify))
	js.Global().Set("bifroestEvidencePlayback", js.FuncOf(playback))
	js.Global().Call("postMessage", map[string]any{"kind": "ready"})
	select {}
}
