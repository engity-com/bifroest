// Package testvectors contains fixed expectations for the published public test
// vectors. It is imported only by tests, never by readers, writers or verifiers.
package testvectors

import "strings"

// Base58Projection changes only the three UUID spellings in the frozen audit
// JSONL examples. Original containers, signatures, hashes, ordering and all other
// output bytes remain exact assertions. Expectations do not use the production
// UUID codec; the original assets and their manifests are never regenerated.
func Base58Projection(data []byte) []byte {
	return []byte(strings.NewReplacer(
		"34e34ab8-7457-4d88-a5e4-c57791775c3a", "7Xng23oeg4L1zHaZfeX6wB",
		"6d05798f-b877-4191-8aa0-4576a30411ad", "ETpbmoUWv7RZ9g3Be6YL6Q",
		"82d8fdda-4730-43b7-bfde-72733c217bde", "HA9F23fnkb8qrdpEfiXj6M",
	).Replace(string(data)))
}
