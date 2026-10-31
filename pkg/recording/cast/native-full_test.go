package cast

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/nativeformat"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func portableNativeVector(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "assets", "recording-format-vectors", "native-v1", name))
	require.NoError(t, err)
	return data
}
func portableNativeKeys(t *testing.T, seedByte byte) *keydata.AgeSshIdentities {
	t.Helper()
	key, err := keydata.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)))
	require.NoError(t, err)
	identities, err := keydata.NewAgeSshIdentities([]keydata.PrivateKey{key})
	require.NoError(t, err)
	return identities
}

type vectorPublicIdentity struct {
	key      keydata.PublicKey
	producer evidence.ProducerId
}

func (v vectorPublicIdentity) PublicKey() keydata.PublicKey    { return v.key }
func (v vectorPublicIdentity) ProducerId() evidence.ProducerId { return v.producer }

func TestPortableNativeFullDecryptVerifyAndExportFrozenEvidence(t *testing.T) {
	_, expected := portableCastVector(t)
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	public, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	require.NoError(t, err)
	key, err := keydata.PublicKeyFromSsh(public)
	require.NoError(t, err)
	for _, name := range []string{"bcast", "becast"} {
		t.Run(name, func(t *testing.T) {
			file := name + "-v1." + name
			data := portableNativeVector(t, file)
			golden := portableNativeVector(t, name+"-v1.cast")
			var identities *keydata.AgeSshIdentities
			if name == "becast" {
				identities = portableNativeKeys(t, 0x42)
			}
			options := NativeRecordingVerifyOptions{ExpectedProducerId: expected}
			outer, err := VerifyNativeRecordingOuter(bytes.NewReader(data), int64(len(data)), options)
			require.NoError(t, err)
			require.True(t, outer.Trusted)
			full, err := VerifyNativeRecordingFull(bytes.NewReader(data), int64(len(data)), identities, options)
			require.NoError(t, err)
			require.Equal(t, outer, full)
			var output bytes.Buffer
			verification, err := ExportNativeRecordingCast(bytes.NewReader(data), int64(len(data)), identities, &output, options)
			require.NoError(t, err)
			require.True(t, verification.Trusted)
			require.Equal(t, golden, output.Bytes())
			cast, err := VerifyCast(bytes.NewReader(output.Bytes()), CastVerifyOptions{ExpectedProducerId: expected})
			require.NoError(t, err)
			require.True(t, cast.Trusted)
			require.EqualValues(t, 7, *cast.ExitStatus)
			head := portableNativeVector(t, name+"-head.cbor")
			require.NoError(t, VerifyNativeRecordingCheckpoint(bytes.NewReader(data), int64(len(data)), head, vectorPublicIdentity{key, expected}, options))
			if name == "becast" {
				for _, wrong := range []*keydata.AgeSshIdentities{nil, portableNativeKeys(t, 0x97)} {
					var denied bytes.Buffer
					denied.WriteString("unchanged")
					_, err := ExportNativeRecordingCast(bytes.NewReader(data), int64(len(data)), wrong, &denied, options)
					require.Error(t, err)
					require.Equal(t, "unchanged", denied.String())
				}
			}
			for _, bad := range [][]byte{data[:len(data)-1], append(bytes.Clone(data), 0), func() []byte { v := bytes.Clone(data); v[len(v)/2] ^= 1; return v }()} {
				var denied bytes.Buffer
				_, err := ExportNativeRecordingCast(bytes.NewReader(bad), int64(len(bad)), identities, &denied, options)
				require.Error(t, err)
				require.Zero(t, denied.Len())
			}
			wrong := options
			wrong.ExpectedProducerId[0] ^= 1
			var denied bytes.Buffer
			_, err = ExportNativeRecordingCast(bytes.NewReader(data), int64(len(data)), identities, &denied, wrong)
			require.Error(t, err)
			require.Zero(t, denied.Len())
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			options.Context = ctx
			_, err = ExportNativeRecordingCast(bytes.NewReader(data), int64(len(data)), identities, &denied, options)
			require.ErrorIs(t, err, context.Canceled)
			require.Zero(t, denied.Len())
		})
	}
}

type mutateAfterOuterHash struct {
	data    []byte
	mutated bool
}

func (this *mutateAfterOuterHash) ReadAt(dst []byte, offset int64) (int, error) {
	n, err := bytes.NewReader(this.data).ReadAt(dst, offset)
	if !this.mutated && offset == 0 && len(dst) > len(nativeformat.RecordingMagic) {
		this.mutated = true
		this.data[len(this.data)/2] ^= 1
	}
	return n, err
}

func TestPortableNativeFullRejectsChangedInputBetweenPasses(t *testing.T) {
	data := portableNativeVector(t, "bcast-v1.bcast")
	_, expected := portableCastVector(t)
	reader := &mutateAfterOuterHash{data: bytes.Clone(data)}
	var output bytes.Buffer
	_, err := ExportNativeRecordingCast(reader, int64(len(data)), nil, &output, NativeRecordingVerifyOptions{ExpectedProducerId: expected})
	require.True(t, reader.mutated)
	require.Error(t, err)
	require.Zero(t, output.Len(), "mutation before full verification must not publish plaintext")
	require.NotEqual(t, sha256.Sum256(data), sha256.Sum256(reader.data))
	_, err = ExportNativeRecordingCast(bytes.NewReader(data), int64(len(data)), nil, nil, NativeRecordingVerifyOptions{ExpectedProducerId: expected})
	require.Error(t, err)
	_, err = ExportNativeRecordingCast(bytes.NewReader(data), int64(len(data)), nil, shortNativeOutput{}, NativeRecordingVerifyOptions{ExpectedProducerId: expected})
	require.ErrorIs(t, err, io.ErrShortWrite)
}

type shortNativeOutput struct{}

func (shortNativeOutput) Write([]byte) (int, error) { return 0, nil }
