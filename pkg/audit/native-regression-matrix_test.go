package audit

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

// Replace a canonical definite-length CBOR map header with its non-minimal
// two-byte form, then frame it with a correct CRC and commit marker.
func noncanonicalNativeAuditUnit(t *testing.T, original []byte) []byte {
	t.Helper()
	length := int(binary.BigEndian.Uint32(original[1:5]))
	require.Len(t, original, 6+length+4+len(nativeformat.CommitMarker))
	payload := original[6 : 6+length]
	require.Equal(t, byte(5), payload[0]>>5)
	require.Less(t, payload[0]&0x1f, byte(24))
	altered := append([]byte{0xb8, payload[0] & 0x1f}, payload[1:]...)
	frame := make([]byte, 6+len(altered)+4+len(nativeformat.CommitMarker))
	frame[0], frame[5] = original[0], 1
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(altered)))
	copy(frame[6:], altered)
	table := crc32.MakeTable(crc32.Castagnoli)
	checksum := crc32.Update(crc32.Checksum(frame[:5], table), table, altered)
	binary.BigEndian.PutUint32(frame[6+len(altered):], checksum)
	copy(frame[6+len(altered)+4:], nativeformat.CommitMarker)
	_, _, _, err := nativeformat.ReadUnitAt(bytes.NewReader(frame), 0, int64(len(frame)), nativeformat.MaxAuditRecordPayload)
	require.ErrorContains(t, err, "canonically encoded")
	return frame
}

func TestNativeAuditPhysicalUnitRegressionMatrix(t *testing.T) {
	identity, err := NewIdentity(auditVectorKey(t, auditVectorSigningSeed))
	require.NoError(t, err)
	recipientKey := auditVectorKey(t, auditVectorRecipientSeed)
	recipient, err := bfcrypto.NewAgeSshRecipient(recipientKey.PublicKey().ToSsh())
	require.NoError(t, err)

	for _, encrypted := range []bool{false, true} {
		name := "clear"
		fingerprint := ""
		if encrypted {
			name, fingerprint = "encrypted", recipient.Fingerprint()
		}
		t.Run(name, func(t *testing.T) {
			vector := frozenAuditVector(t, encrypted)
			headerUnit, _, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(vector.header), 0, int64(len(vector.header)), nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			require.False(t, tail)
			header, err := nativeformat.Unmarshal[nativeAuditHeader](headerUnit.Payload, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			header.Encryption ^= 1
			unsigned, err := nativeformat.Marshal(nativeAuditHeaderFields(header), nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			header.Signature, err = identity.sign(append([]byte(nativeAuditHeaderSignatureDomain), unsigned...))
			require.NoError(t, err)
			require.NoError(t, identity.verify(append([]byte(nativeAuditHeaderSignatureDomain), unsigned...), header.Signature))
			modePayload, err := nativeformat.Marshal(header, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			modeFrame, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, modePayload, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			_, err = decodeNativeAuditHeader(modePayload, identity, 1, journalHash{}, journalHash{}, fingerprint)
			require.ErrorContains(t, err, "native audit header identity, mode or chain mismatch")
			_, split, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(vector.records), 0, int64(len(vector.records)), nativeformat.MaxAuditRecordPayload)
			require.NoError(t, err)
			require.False(t, tail)
			first, second := vector.records[:split], vector.records[split:]
			_, end, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(second), 0, int64(len(second)), nativeformat.MaxAuditRecordPayload)
			require.NoError(t, err)
			require.False(t, tail)
			require.EqualValues(t, len(second), end)

			assemble := func(units ...[]byte) []byte {
				return bytes.Join(append([][]byte{[]byte(nativeformat.AuditMagic)}, units...), nil)
			}
			cases := []struct {
				name    string
				segment []byte
				restart bool
			}{
				{"missing header", assemble(first, second, vector.seal), false},
				{"missing second record", assemble(vector.header, first, vector.seal), true},
				{"duplicate first record", assemble(vector.header, first, first, second, vector.seal), false},
				{"swapped records", assemble(vector.header, second, first, vector.seal), false},
				{"duplicate header", assemble(vector.header, vector.header, first, second, vector.seal), true},
				{"duplicate seal", assemble(vector.header, first, second, vector.seal, vector.seal), false},
				{"missing seal", assemble(vector.header, first, second), false},
				{"trailing bytes", append(assemble(vector.header, first, second, vector.seal), 0, 1, 2), false},
				{"signed mode mismatch", assemble(modeFrame, first, second, vector.seal), true},
				{"noncanonical header", assemble(noncanonicalNativeAuditUnit(t, vector.header), first, second, vector.seal), false},
				{"noncanonical record", assemble(vector.header, noncanonicalNativeAuditUnit(t, first), second, vector.seal), true},
				{"noncanonical seal", assemble(vector.header, first, second, noncanonicalNativeAuditUnit(t, vector.seal)), false},
			}
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					root := t.TempDir()
					producer := filepath.Join(root, identity.ProducerId().String())
					require.NoError(t, os.Mkdir(producer, 0700))
					headPath := filepath.Join(producer, nativeHeadFileName)
					segmentPath := filepath.Join(producer, nativeSegmentName(1, hashNativeAuditSegment(test.segment), encrypted))
					require.NoError(t, os.WriteFile(headPath, vector.head, 0600))
					require.NoError(t, os.WriteFile(segmentPath, test.segment, 0600))
					source := JournalSource{Name: "regression", Directory: root, ExpectedProducerId: identity.ProducerId(), ExpectedEncryptionRecipient: fingerprint}
					require.Error(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}))
					verified, err := VerifyJournals(context.Background(), []JournalSource{source})
					require.Error(t, err)
					require.Nil(t, verified, "failed verification must not expose records for plaintext export")
					if test.restart {
						conf := auditIdentityTestConfiguration(root, true)
						conf.Directory = root
						if encrypted {
							conf.EncryptionPublicKey = bfcrypto.PublicKeys(string(ssh.MarshalAuthorizedKey(recipientKey.PublicKey().ToSsh())))
						}
						recorder, err := newNativeRecorder(&conf, identity)
						require.Error(t, err, "restart must reject the altered published segment")
						require.Nil(t, recorder)
					}
					stored, err := os.ReadFile(segmentPath)
					require.NoError(t, err)
					require.Equal(t, test.segment, stored)
					stored, err = os.ReadFile(headPath)
					require.NoError(t, err)
					require.Equal(t, vector.head, stored)
				})
			}
		})
	}
}
