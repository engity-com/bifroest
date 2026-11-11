//go:build ignore

// Native test helper only. Browser actions never invoke Go/CLI subprocesses.
package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"

	"github.com/engity-com/bifroest/pkg/browserauth"
)

func main() {
	input, output := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	var key browserauth.PublicKey
	if err := input.Decode(&key); err != nil {
		log.Fatal(err)
	}
	proof, err := browserauth.NewChallenge(key, browserauth.Context{
		Purpose: "resume", Origin: "https://app.example.org", Slug: "Work",
		Flow: "work", SessionID: "70d5159d-a0e4-46ca-b011-c4f831f4ade0",
		BindingID: "bbr1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Revision: 1,
		Target: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := output.Encode(base64.StdEncoding.EncodeToString(proof.Bytes())); err != nil {
		log.Fatal(err)
	}
	var encoded string
	if err := input.Decode(&encoded); err != nil {
		log.Fatal(err)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		log.Fatal(err)
	}
	if err := proof.Verify(signature); err != nil {
		log.Fatal(err)
	}
	if err := output.Encode(true); err != nil {
		log.Fatal(err)
	}
}
