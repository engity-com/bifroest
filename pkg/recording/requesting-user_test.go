package recording

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func TestRecordingRequestingUserIsOptionalBoundedUTF8Metadata(t *testing.T) {
	identity, header, metadata := castTestValues(t, false)
	for _, user := range []string{"", "Original-Requesting-Name", strings.Repeat("é", 128)} {
		metadata.User = user
		encoded, err := json.Marshal(metadata)
		require.NoError(t, err)
		if user == "" {
			require.NotContains(t, string(encoded), `"user"`, "legacy metadata must retain exactly its existing fields")
		}
		var output bytes.Buffer
		writer, err := NewCastWriter(&output, identity, header, metadata)
		require.NoError(t, err)
		_, err = writer.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
		require.NoError(t, err)
		verified, err := VerifyCast(bytes.NewReader(output.Bytes()), CastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
		require.NoError(t, err)
		require.Equal(t, user, verified.Metadata.User)
		setup, err := EncodeNativeRecordingEvents([]NativeCastEvent{{Kind: NativeEventSetup, Header: header, Metadata: metadata}})
		require.NoError(t, err)
		events, err := decodeNativeRecordingEvents(setup)
		require.NoError(t, err)
		require.Equal(t, user, events[0].Metadata.User)
	}
	for _, user := range []string{"invalid\xff", "invalid\nname", "invalid\x00name", "invalid\x7fname", "invalid\u0085name", strings.Repeat("x", 257), strings.Repeat("é", 129)} {
		metadata.User = user
		require.Error(t, metadata.ValidateRequestingUser(), "explicitly invalid metadata remains an error even though transport capture may omit the optional field")
		var cast, native bytes.Buffer
		_, err := NewCastWriter(&cast, identity, header, metadata)
		require.Error(t, err)
		require.Zero(t, cast.Len(), "invalid names cannot publish a partial recording")
		_, err = NewNativeRecordingWriter(&native, identity, nil, header, metadata, 0, NativeRecordingWriterLimits{})
		require.Error(t, err)
		require.Zero(t, native.Len())
		_, err = EncodeNativeRecordingEvents([]NativeCastEvent{{Kind: NativeEventSetup, Header: header, Metadata: metadata}})
		require.Error(t, err)
	}
	metadata.User = ""
	setup, err := EncodeNativeRecordingEvents([]NativeCastEvent{{Kind: NativeEventSetup, Header: header, Metadata: metadata}})
	require.NoError(t, err)
	root, err := nativeformat.Unmarshal[map[uint64]any](setup, nativeformat.MaxRecordingDecodedChunk)
	require.NoError(t, err)
	meta := root[2].([]any)[0].(map[any]any)[uint64(3)].(map[any]any)
	_, present := meta[uint64(10)]
	require.False(t, present, "the optional private key must not change legacy event bytes")
	for _, invalid := range []any{"", "invalid\nname", strings.Repeat("é", 129), uint64(1), []byte("binary-not-a-user")} {
		meta[uint64(10)] = invalid
		malformed, err := nativeformat.Marshal(root, nativeformat.MaxRecordingDecodedChunk)
		require.NoError(t, err)
		events, err := decodeNativeRecordingEvents(malformed)
		require.Error(t, err)
		require.Nil(t, events)
	}
	meta[uint64(10)] = nil
	_, err = nativeformat.Marshal(root, nativeformat.MaxRecordingDecodedChunk)
	require.Error(t, err, "null metadata is already forbidden by the shared native encoder")
}

func TestRecordingRequestingUserRemainsPrivateInEncryptedNativeArtifacts(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			identity, header, metadata := castTestValues(t, false)
			metadata.User = "Original-Requesting-User-Private-Metadata-Only"
			var recipient *bfcrypto.AgeSshRecipient
			var keys *bfcrypto.AgeSshIdentities
			if encrypted {
				recipient, keys = newBECastTestEncryption(t)
			}
			root := t.TempDir()
			repository, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, repository.Close()) })
			active, err := repository.CreateActive(t.Context(), header, metadata, 300)
			require.NoError(t, err)
			require.NoError(t, active.WriteOutput(time.Millisecond, OutputStreamStdout, []byte("output is not identity")))
			summary, err := active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
			require.NoError(t, err)
			artifact, err := repository.OpenSealed(t.Context(), metadata.RecordingId)
			require.NoError(t, err)
			require.Equal(t, summary, artifact.Summary())
			path := filepath.Join(root, localSealedDirectory, artifact.FileName())
			content, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, artifact.Close())
			inspection, err := Inspect(bytes.NewReader(content), int64(len(content)), InspectOptions{ExpectedProducerId: identity.ProducerId()})
			require.NoError(t, err)
			rows, err := repository.CatalogMetadata(t.Context())
			require.NoError(t, err)
			require.Len(t, rows, 1)
			if encrypted {
				require.Empty(t, summary.User)
				require.Empty(t, rows[0].User)
				require.Nil(t, inspection.Metadata)
				require.NotContains(t, string(content), metadata.User)
			} else {
				require.Equal(t, metadata.User, summary.User)
				require.Equal(t, metadata.User, rows[0].User)
				require.NotNil(t, inspection.Metadata)
				require.Equal(t, metadata.User, inspection.Metadata.User)
			}
			_, err = VerifyNativeRecordingOuter(bytes.NewReader(content), int64(len(content)), NativeRecordingVerifyOptions{
				ExpectedProducerId: identity.ProducerId(), VerifiedMetadata: func(CastMetadata) { t.Fatal("outer verification must not expose private metadata") },
			})
			require.NoError(t, err)
			var fullMetadata *CastMetadata
			_, err = VerifyNativeRecordingFull(bytes.NewReader(content), int64(len(content)), keys, NativeRecordingVerifyOptions{
				ExpectedProducerId: identity.ProducerId(), VerifiedMetadata: func(value CastMetadata) { fullMetadata = &value },
			})
			require.NoError(t, err)
			require.NotNil(t, fullMetadata)
			require.Equal(t, metadata.User, fullMetadata.User)
			var exported bytes.Buffer
			_, err = ExportNativeRecordingCast(bytes.NewReader(content), int64(len(content)), keys, &exported, NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()})
			require.NoError(t, err)
			cast, err := VerifyCast(bytes.NewReader(exported.Bytes()), CastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
			require.NoError(t, err)
			require.Equal(t, metadata.User, cast.Metadata.User)
			require.NoError(t, filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil || entry.IsDir() || current == path {
					return walkErr
				}
				auxiliary, err := os.ReadFile(current)
				require.NoError(t, err)
				require.NotContains(t, string(auxiliary), metadata.User, "private context must not spill into unsigned heads or summary sidecars: %s", current)
				return nil
			}))
		})
	}
}
