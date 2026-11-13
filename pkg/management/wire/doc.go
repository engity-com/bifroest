// Package wire implements the existing bounded management framing over ordinary
// Reader/Writer streams. It has no SSH, CLI, filesystem or authentication layer.
// Command names/argument envelopes are legacy SSH framing, not a browser API.
//
// Successful decoding proves framing, declared lengths/counts, digests and EOF
// only, never producer trust, signatures or decryption. Stream callbacks/writes
// are provisional until decoding AND the owning transport's completion succeed.
// Callers own cancellation/unblocking of I/O and staging/cleanup/publication.
package wire
