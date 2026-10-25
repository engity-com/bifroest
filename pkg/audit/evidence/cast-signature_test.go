package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestPortableCastSignatureRetainsExactDomainAndLegacyFields(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	public, err := ssh.NewPublicKey(private.Public())
	require.NoError(t, err)
	value := SessionRecordingCastSignature{Schema: SessionRecordingCastSignatureSchema, RecordingId: "00112233-4455-4677-8899-aabbccddeeff", ProducerId: ProducerId(sha256.Sum256(public.Marshal())), Digest: strings.Repeat("0", 64), PublicKey: public.Marshal()}
	message, err := SessionRecordingCastSignatureMessage(value)
	require.NoError(t, err)
	// Independent frozen pre-extraction field layout/order and fixed domain.
	legacy := struct {
		Schema      string     `json:"schema"`
		RecordingId string     `json:"recordingId"`
		ProducerId  ProducerId `json:"producerId"`
		Digest      string     `json:"digest"`
		PublicKey   []byte     `json:"publicKey"`
	}{value.Schema, value.RecordingId, value.ProducerId, value.Digest, value.PublicKey}
	encoded, err := json.Marshal(legacy)
	require.NoError(t, err)
	require.Equal(t, append([]byte("BIFROEST-ASCIICAST-SIGNATURE/v1\x00"), encoded...), message)
	value.Signature = ed25519.Sign(private, message)
	verified, err := VerifySessionRecordingCastSignature(value)
	require.NoError(t, err)
	require.Equal(t, public.Marshal(), verified.Marshal())
	for _, mutate := range []func(*SessionRecordingCastSignature){func(v *SessionRecordingCastSignature) { v.Schema = "other" }, func(v *SessionRecordingCastSignature) { v.RecordingId = "bad" }, func(v *SessionRecordingCastSignature) { v.ProducerId[0] ^= 1 }, func(v *SessionRecordingCastSignature) { v.Digest = strings.Repeat("A", 64) }, func(v *SessionRecordingCastSignature) { v.Digest = strings.Repeat("1", 64) }, func(v *SessionRecordingCastSignature) { v.PublicKey = append(bytes.Clone(v.PublicKey), 0) }, func(v *SessionRecordingCastSignature) { v.Signature = bytes.Clone(v.Signature); v.Signature[0] ^= 1 }} {
		bad := value
		mutate(&bad)
		key, err := VerifySessionRecordingCastSignature(bad)
		require.Error(t, err)
		require.Nil(t, key)
	}
}
