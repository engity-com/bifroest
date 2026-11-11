package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

type codecVectorHashes struct {
	RecordHashes []string `json:"recordHashes"`
	ContentHash  string   `json:"contentHash"`
	SegmentHash  string   `json:"segmentHash"`
}

type codecVectorManifest struct {
	Schema               string            `json:"schema"`
	SigningSeedHex       string            `json:"signingSeedHex"`
	AgeRecipientSeedHex  string            `json:"ageRecipientSeedHex"`
	ProducerId           string            `json:"producerId"`
	RecipientFingerprint string            `json:"recipientFingerprint"`
	Clear                codecVectorHashes `json:"clear"`
	Encrypted            codecVectorHashes `json:"encrypted"`
	Artifacts            []struct {
		Path   string `json:"path"`
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"artifacts"`
}

func readCodecVector(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "assets", "audit-format-vectors", "v1", name))
	require.NoError(t, err)
	return data
}

func codecManifest(t *testing.T) codecVectorManifest {
	t.Helper()
	var manifest codecVectorManifest
	require.NoError(t, json.Unmarshal(readCodecVector(t, "manifest.json"), &manifest))
	require.Equal(t, "bifroest.audit-format-vectors/v1", manifest.Schema)
	// Independent producer expectation: never derive trust from an input head.
	require.Equal(t, "95b9aca00d322047048950d19cc5aece6fa757edd9104a5521446a168792b298", manifest.ProducerId)
	for _, artifact := range manifest.Artifacts {
		data := readCodecVector(t, artifact.Path)
		digest := sha256.Sum256(data)
		require.Equal(t, artifact.Bytes, len(data), artifact.Path)
		require.Equal(t, artifact.SHA256, hex.EncodeToString(digest[:]), artifact.Path)
	}
	return manifest
}

func codecPrivateKey(t *testing.T, seedHex string) keydata.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	require.NoError(t, err)
	require.Len(t, seed, ed25519.SeedSize)
	key, err := keydata.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	return key
}

func codecPublicIdentity(t *testing.T, key keydata.PrivateKey) *PublicIdentity {
	t.Helper()
	encoded := key.PublicKey().Marshal()
	identity, err := NewPublicIdentity(ProducerId(sha256.Sum256(encoded)), encoded)
	require.NoError(t, err)
	return identity
}

func codecUnits(t *testing.T, data []byte) ([]nativeformat.Unit, []int64) {
	t.Helper()
	require.True(t, bytes.HasPrefix(data, []byte(nativeformat.AuditMagic)))
	var units []nativeformat.Unit
	var offsets []int64
	for offset := int64(len(nativeformat.AuditMagic)); offset < int64(len(data)); {
		unit, next, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(data), offset, int64(len(data)), nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		require.False(t, tail)
		offsets = append(offsets, offset)
		units = append(units, unit)
		offset = next
	}
	require.Len(t, units, 4)
	require.Equal(t, nativeformat.HeaderUnit, units[0].Type)
	require.Equal(t, nativeformat.ContentUnit, units[1].Type)
	require.Equal(t, nativeformat.ContentUnit, units[2].Type)
	require.Equal(t, nativeformat.SealUnit, units[3].Type)
	return units, offsets
}

// These are unit-codec interoperability tests, not a portable journal verifier.
// Inventory, immutable-reader ownership and final tree revalidation are separate.
func TestPortableAuditCodecsReadFrozenClearAndAgeUnits(t *testing.T) {
	manifest := codecManifest(t)
	identity := codecPublicIdentity(t, codecPrivateKey(t, manifest.SigningSeedHex))
	require.Equal(t, manifest.ProducerId, identity.ProducerId().String())
	key := codecPrivateKey(t, manifest.AgeRecipientSeedHex)
	identities, err := keydata.NewAgeSshIdentities([]keydata.PrivateKey{key})
	require.NoError(t, err)
	for _, encrypted := range []bool{false, true} {
		name, extension, recipient, hashes := "baudit-v1", ".baudit", "", manifest.Clear
		if encrypted {
			name, extension, recipient, hashes = "beaudit-v1", ".beaudit", manifest.RecipientFingerprint, manifest.Encrypted
		}
		t.Run(name, func(t *testing.T) {
			data := readCodecVector(t, name+extension)
			units, offsets := codecUnits(t, data)
			header, err := DecodeAuditHeader(units[0].Payload, identity, 1, Hash{}, Hash{}, recipient)
			require.NoError(t, err)
			require.Equal(t, recipient, header.Recipient)
			var previous Hash
			for index := 0; index < 2; index++ {
				payload := units[index+1].Payload
				record, redacted, hash, err := DecodeAuditRecord(payload, identity, previous, recipient, nil, false)
				require.NoError(t, err)
				require.Equal(t, hashes.RecordHashes[index], hash.String())
				require.Equal(t, previous, Hash(record.PreviousRecordHash))
				_, full, fullHash, err := DecodeAuditRecord(payload, identity, previous, recipient, identities, true)
				require.NoError(t, err)
				require.Equal(t, hash, fullHash)
				require.Equal(t, Event{Name: full.Name, Domain: full.Domain, Outcome: full.Outcome}, redacted)
				require.Equal(t, "fixture-flow", full.Flow)
				if index == 0 {
					require.Equal(t, "custom.authentication", full.Name)
					require.Equal(t, AuthenticationMethodPublicKey, full.AuthenticationMethod)
					require.Equal(t, AuthenticationPhaseVerified, full.AuthenticationPhase)
					require.Equal(t, "34e34ab8-7457-4d88-a5e4-c57791775c3a", uuid.UUID(record.Id).String())
				} else {
					require.Equal(t, "custom.session", full.Name)
					require.Equal(t, "82d8fdda-4730-43b7-bfde-72733c217bde", full.SessionId)
					require.Equal(t, SessionTaskExec, full.SessionTask)
					require.Equal(t, EventReasonAuthorizedKeyPolicy, full.Reason)
				}
				previous = hash
			}
			content := HashAuditContent(data[:offsets[3]])
			require.Equal(t, hashes.ContentHash, content.String())
			require.Equal(t, hashes.SegmentHash, HashAuditSegment(data).String())
			require.NotEqual(t, content, HashAuditSegment(data))
			seal, err := DecodeAuditSeal(units[3].Payload, identity, 1, 2, uint64(offsets[3]), content, previous)
			require.NoError(t, err)
			require.Equal(t, previous, Hash(seal.LastRecordHash))
			head, err := DecodeAuditHead(readCodecVector(t, name+"-head.cbor"), identity)
			require.NoError(t, err)
			require.Equal(t, previous, Hash(head.LastRecordHash))
			if encrypted {
				wrong, err := keydata.NewAgeSshIdentities([]keydata.PrivateKey{codecPrivateKey(t, manifest.SigningSeedHex)})
				require.NoError(t, err)
				for _, keys := range []*keydata.AgeSshIdentities{nil, wrong} {
					record, event, hash, err := DecodeAuditRecord(units[1].Payload, identity, Hash{}, recipient, keys, true)
					require.Error(t, err)
					require.Equal(t, NativeAuditRecord{}, record)
					require.Equal(t, Event{}, event)
					require.True(t, hash.IsZero())
				}
			}
		})
	}
}

func TestPortableAuditCodecsRejectWrongIdentityBindingsAndTampering(t *testing.T) {
	manifest := codecManifest(t)
	identity := codecPublicIdentity(t, codecPrivateKey(t, manifest.SigningSeedHex))
	other := codecPublicIdentity(t, codecPrivateKey(t, manifest.AgeRecipientSeedHex))
	data := readCodecVector(t, "baudit-v1.baudit")
	units, offsets := codecUnits(t, data)
	for _, candidate := range []JournalIdentity{nil, (*PublicIdentity)(nil), &PublicIdentity{}, other} {
		header, err := DecodeAuditHeader(units[0].Payload, candidate, 1, Hash{}, Hash{}, "")
		require.Error(t, err)
		require.Equal(t, NativeAuditHeader{}, header)
		record, event, hash, err := DecodeAuditRecord(units[1].Payload, candidate, Hash{}, "", nil, false)
		require.Error(t, err)
		require.Equal(t, NativeAuditRecord{}, record)
		require.Equal(t, Event{}, event)
		require.True(t, hash.IsZero())
		var last Hash
		require.NoError(t, last.UnmarshalText([]byte(manifest.Clear.RecordHashes[1])))
		seal, err := DecodeAuditSeal(units[3].Payload, candidate, 1, 2, uint64(offsets[3]), HashAuditContent(data[:offsets[3]]), last)
		require.Error(t, err)
		require.Equal(t, NativeAuditSeal{}, seal)
		head, err := DecodeAuditHead(readCodecVector(t, "baudit-v1-head.cbor"), candidate)
		require.Error(t, err)
		require.Equal(t, NativeAuditHead{}, head)
	}
	for _, sequence := range []uint64{0, 2} {
		_, err := DecodeAuditHeader(units[0].Payload, identity, sequence, Hash{}, Hash{}, "")
		require.Error(t, err)
	}
	_, err := DecodeAuditHeader(units[0].Payload, identity, 1, Hash{1}, Hash{}, "")
	require.Error(t, err)
	_, err = DecodeAuditHeader(units[0].Payload, identity, 1, Hash{}, Hash{1}, "")
	require.Error(t, err)
	_, err = DecodeAuditHeader(units[0].Payload, identity, 1, Hash{}, Hash{}, manifest.RecipientFingerprint)
	require.Error(t, err)
	for _, payload := range [][]byte{
		append(bytes.Clone(units[1].Payload), 0),
		units[1].Payload[:len(units[1].Payload)-1],
	} {
		record, event, hash, err := DecodeAuditRecord(payload, identity, Hash{}, "", nil, false)
		require.Error(t, err)
		require.Equal(t, NativeAuditRecord{}, record)
		require.Equal(t, Event{}, event)
		require.True(t, hash.IsZero())
	}
	record, err := nativeformat.Unmarshal[NativeAuditRecord](units[1].Payload, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	record.PrivatePayload[0] ^= 1
	malicious, err := nativeformat.Marshal(record, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, malicious, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	framed, _, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(frame), 0, int64(len(frame)), nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	require.False(t, tail)
	_, _, _, err = DecodeAuditRecord(framed.Payload, identity, Hash{}, "", nil, false)
	require.Error(t, err, "a valid transport CRC never repairs an evidence signature")
}

func TestPortableAuditCodecsRejectTamperedMetadataAndSealBindings(t *testing.T) {
	manifest := codecManifest(t)
	identity := codecPublicIdentity(t, codecPrivateKey(t, manifest.SigningSeedHex))
	data := readCodecVector(t, "baudit-v1.baudit")
	units, offsets := codecUnits(t, data)
	header, err := nativeformat.Unmarshal[NativeAuditHeader](units[0].Payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	header.Signature[0] ^= 1
	payload, err := nativeformat.Marshal(header, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	header, err = DecodeAuditHeader(payload, identity, 1, Hash{}, Hash{}, "")
	require.Error(t, err)
	require.Equal(t, NativeAuditHeader{}, header)

	head, err := nativeformat.Unmarshal[NativeAuditHead](readCodecVector(t, "baudit-v1-head.cbor"), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	head.LastRecordHash[0] ^= 1
	payload, err = nativeformat.Marshal(head, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	head, err = DecodeAuditHead(payload, identity)
	require.Error(t, err)
	require.Equal(t, NativeAuditHead{}, head)

	var last Hash
	require.NoError(t, last.UnmarshalText([]byte(manifest.Clear.RecordHashes[1])))
	content := HashAuditContent(data[:offsets[3]])
	seal, err := nativeformat.Unmarshal[NativeAuditSeal](units[3].Payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	seal.Signature[0] ^= 1
	payload, err = nativeformat.Marshal(seal, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	seal, err = DecodeAuditSeal(payload, identity, 1, 2, uint64(offsets[3]), content, last)
	require.Error(t, err)
	require.Equal(t, NativeAuditSeal{}, seal)
	for _, binding := range []struct {
		sequence, count, size uint64
		content, last         Hash
	}{
		{2, 2, uint64(offsets[3]), content, last},
		{1, 3, uint64(offsets[3]), content, last},
		{1, 2, uint64(offsets[3]) + 1, content, last},
		{1, 2, uint64(offsets[3]), Hash{1}, last},
		{1, 2, uint64(offsets[3]), content, Hash{1}},
	} {
		seal, err = DecodeAuditSeal(units[3].Payload, identity, binding.sequence, binding.count, binding.size, binding.content, binding.last)
		require.Error(t, err)
		require.Equal(t, NativeAuditSeal{}, seal)
	}
	record, event, hash, err := DecodeAuditRecord(units[1].Payload, identity, Hash{1}, "", nil, false)
	require.Error(t, err)
	require.Equal(t, NativeAuditRecord{}, record)
	require.Equal(t, Event{}, event)
	require.True(t, hash.IsZero())
}

func signCodecTestRecord(t *testing.T, key keydata.PrivateKey, record NativeAuditRecord) []byte {
	t.Helper()
	unsigned, err := nativeformat.Marshal(AuditRecordFields(record), nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	// Test-only signing of deliberately invalid evidence; no production signer
	// capability is added to the portable journal package.
	private, ok := key.ToSdk().(ed25519.PrivateKey)
	require.True(t, ok)
	record.Signature = ed25519.Sign(private, append([]byte(AuditRecordSignatureDomain), unsigned...))
	payload, err := nativeformat.Marshal(record, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	return payload
}

func TestPortableAuditCodecsDoNotConfuseOuterAuthenticationWithPrivateSemantics(t *testing.T) {
	manifest := codecManifest(t)
	key := codecPrivateKey(t, manifest.SigningSeedHex)
	identity := codecPublicIdentity(t, key)
	recipientKey := codecPrivateKey(t, manifest.AgeRecipientSeedHex)
	recipient, err := keydata.NewAgeSshRecipient(recipientKey.PublicKey().ToSsh())
	require.NoError(t, err)
	identities, err := keydata.NewAgeSshIdentities([]keydata.PrivateKey{recipientKey})
	require.NoError(t, err)
	for _, encrypted := range []bool{false, true} {
		var selected *keydata.AgeSshRecipient
		fingerprint := ""
		if encrypted {
			selected, fingerprint = recipient, recipient.Fingerprint()
		}
		for _, public := range []NativeAuditPublicEvent{
			{Name: "custom.invalid-count"},
			{Name: EventNameSessionRecordingCompleted, Domain: string(EventDomainSession), Outcome: string(EventOutcomeSuccess)},
		} {
			private := NativeAuditPrivateEvent{}
			if public.Name == "custom.invalid-count" {
				private.Count = new(uint64)
			}
			plain, err := nativeformat.Marshal(private, nativeformat.MaxAuditEventPayload)
			require.NoError(t, err)
			stored, err := nativeformat.EncodeStoredPayload(plain, selected, AuditPayloadLimits())
			require.NoError(t, err)
			payload := signCodecTestRecord(t, key, NativeAuditRecord{
				Id:          [16]byte(uuid.MustParse("34e34ab8-7457-4d88-a5e4-c57791775c3a")),
				RecordedAt:  nativeformat.TimestampOf(time.Date(2026, 9, 13, 12, 34, 56, 0, time.UTC)),
				PublicEvent: public, PrivatePayload: stored,
			})
			_, _, _, err = DecodeAuditRecord(payload, identity, Hash{}, fingerprint, nil, false)
			if encrypted {
				require.NoError(t, err, "outer-only authentication cannot attest private semantics")
			} else {
				require.Error(t, err, "redaction must not bypass clear private semantics")
			}
			record, event, hash, err := DecodeAuditRecord(payload, identity, Hash{}, fingerprint, identities, true)
			require.Error(t, err)
			require.Equal(t, NativeAuditRecord{}, record)
			require.Equal(t, Event{}, event)
			require.True(t, hash.IsZero())
		}
	}
}

func TestPortableAuditPublicIdentityOwnsAndValidatesItsPublicKey(t *testing.T) {
	manifest := codecManifest(t)
	key := codecPrivateKey(t, manifest.SigningSeedHex)
	encoded := key.PublicKey().Marshal()
	id := ProducerId(sha256.Sum256(encoded))
	identity, err := NewPublicIdentity(id, encoded)
	require.NoError(t, err)
	encoded[0] ^= 1
	returned := identity.PublicKeyBytes()
	returned[0] ^= 1
	require.Equal(t, key.PublicKey().Marshal(), identity.PublicKeyBytes())
	_, err = DecodeAuditHead(readCodecVector(t, "baudit-v1-head.cbor"), identity)
	require.NoError(t, err)
	for _, bad := range [][]byte{encoded, append(key.PublicKey().Marshal(), 0)} {
		value, err := NewPublicIdentity(id, bad)
		require.Error(t, err)
		require.Nil(t, value)
		value, err = NewPublicIdentity(ProducerId(sha256.Sum256(bad)), bad)
		require.Error(t, err, "hash consistency alone must not accept a malformed/noncanonical SSH key")
		require.Nil(t, value)
	}
}
