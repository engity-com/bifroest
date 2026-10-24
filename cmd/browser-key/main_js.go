//go:build js && wasm

// Browser-only bridge. No server entry point accepts these private arguments.
package main

import (
	"syscall/js"
	"time"

	"github.com/engity-com/bifroest/pkg/browserkey"
)

var imported *browserkey.Key
var attempted bool

func failure() any { return map[string]any{"ok": false} }

func bytes(value js.Value, maximum int) []byte {
	length := value.Get("byteLength").Int()
	if length < 0 || length > maximum || !value.InstanceOf(js.Global().Get("Uint8Array")) {
		panic("invalid private buffer")
	}
	result := make([]byte, length)
	if js.CopyBytesToGo(result, value) != length {
		panic("invalid private buffer")
	}
	return result
}

func open(_ js.Value, args []js.Value) (result any) {
	result = failure()
	defer func() {
		if recover() != nil {
			result = failure()
		}
	}()
	if attempted {
		return result
	}
	attempted = true
	if len(args) != 6 {
		return result
	}
	private := bytes(args[0], browserkey.MaxPrivateKeyBytes)
	defer clear(private)
	passphrase := bytes(args[1], browserkey.MaxPassphraseBytes)
	defer clear(passphrase)
	certificate := bytes(args[2], browserkey.MaxCertificateBytes)
	defer clear(certificate)
	for _, arg := range args[3:] {
		if arg.Type() != js.TypeString {
			return result
		}
	}
	scope := browserkey.Scope{Origin: args[3].String(), Slug: args[4].String(), User: args[5].String()}
	var err error
	imported, err = browserkey.Import(private, passphrase, certificate, scope)
	if err != nil {
		return result
	}
	return map[string]any{"ok": true, "publicKey": imported.PublicKey(), "fingerprint": imported.Fingerprint()}
}

func sign(_ js.Value, args []js.Value) (result any) {
	result = failure()
	defer func() {
		if recover() != nil {
			result = failure()
		}
	}()
	key := imported
	imported = nil
	if key == nil {
		return result
	}
	defer key.Close()
	if len(args) != 2 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeString {
		return result
	}
	encoded, expiry := args[0].String(), args[1].String()
	if len(encoded) > 12<<10 || len(expiry) > 64 {
		return result
	}
	expires, err := time.Parse(time.RFC3339Nano, expiry)
	if err != nil {
		return result
	}
	proof, err := key.Sign(encoded, expires)
	if err != nil {
		return result
	}
	return map[string]any{"ok": true, "signature": proof}
}

func main() {
	js.Global().Set("bifroestKeyImport", js.FuncOf(open))
	js.Global().Set("bifroestKeySign", js.FuncOf(sign))
	js.Global().Call("postMessage", map[string]any{"kind": "ready"})
	select {}
}
