package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRemoteArtifactMetadataContentAndValidation(t *testing.T) {
	artifact := validRemoteArtifactTest()
	require.NoError(t, artifact.Validate())
	require.Equal(t, ProducerId{1}, artifact.ProducerId())
	require.Equal(t, "recording.cast.zst", artifact.FileName())
	require.Equal(t, artifact.ProducerId().String()+"/"+artifact.FileName(), artifact.RemotePath())
	require.Equal(t, int64(len("sealed recording")), artifact.Size())
	first, err := io.ReadAll(artifact.Content())
	require.NoError(t, err)
	second, err := io.ReadAll(artifact.Content())
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, ArtifactDigest(sha256.Sum256(first)), artifact.Digest())

	encoded, err := artifact.Digest().MarshalText()
	require.NoError(t, err)
	var decoded ArtifactDigest
	require.NoError(t, decoded.UnmarshalText(encoded))
	require.Equal(t, artifact.Digest(), decoded)
	require.Error(t, decoded.UnmarshalText([]byte(strings.ToUpper(strings.Repeat("ab", sha256.Size)))))
}

func TestRemoteArtifactRejectsInvalidMetadata(t *testing.T) {
	content := []byte("sealed recording")
	digest := ArtifactDigest(sha256.Sum256(content))
	var nilReader *bytes.Reader
	tests := []struct {
		name     string
		producer ProducerId
		fileName string
		digest   ArtifactDigest
		size     int64
		content  io.ReaderAt
		err      string
	}{
		{"producer", ProducerId{}, "recording.cast.zst", digest, int64(len(content)), bytes.NewReader(content), "producer ID"},
		{"empty-name", ProducerId{1}, "", digest, int64(len(content)), bytes.NewReader(content), "file name"},
		{"slash", ProducerId{1}, "nested/recording.cast.zst", digest, int64(len(content)), bytes.NewReader(content), "file name"},
		{"backslash", ProducerId{1}, `nested\recording.cast.zst`, digest, int64(len(content)), bytes.NewReader(content), "file name"},
		{"leading-dot", ProducerId{1}, ".recording", digest, int64(len(content)), bytes.NewReader(content), "file name"},
		{"space", ProducerId{1}, "recording cast.zst", digest, int64(len(content)), bytes.NewReader(content), "file name"},
		{"long-name", ProducerId{1}, strings.Repeat("a", maximumRemoteArtifactFileNameBytes+1), digest, int64(len(content)), bytes.NewReader(content), "file name"},
		{"digest", ProducerId{1}, "recording.cast.zst", ArtifactDigest{}, int64(len(content)), bytes.NewReader(content), "digest"},
		{"size", ProducerId{1}, "recording.cast.zst", digest, 0, bytes.NewReader(content), "size"},
		{"content", ProducerId{1}, "recording.cast.zst", digest, int64(len(content)), nil, "content"},
		{"typed-nil", ProducerId{1}, "recording.cast.zst", digest, int64(len(content)), nilReader, "content"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRemoteArtifact(test.producer, test.fileName, test.digest, test.size, test.content)
			require.ErrorContains(t, err, test.err)
		})
	}
}

func TestRemoteArtifactRejectsInvalidContent(t *testing.T) {
	content := []byte("sealed recording")
	digest := ArtifactDigest(sha256.Sum256(content))
	tests := []struct {
		name    string
		digest  ArtifactDigest
		size    int64
		content []byte
		err     string
	}{
		{"short-size", digest, int64(len(content) - 1), content, "exceeds declared size"},
		{"long-size", digest, int64(len(content) + 1), content, "content size"},
		{"wrong-digest", ArtifactDigest{1}, int64(len(content)), content, "does not match digest"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifact, err := NewRemoteArtifact(ProducerId{1}, "recording.cast.zst", test.digest, test.size, bytes.NewReader(test.content))
			require.NoError(t, err)
			require.ErrorContains(t, artifact.Validate(), test.err)
		})
	}
}

func TestRemoteArtifactValidationHonorsContext(t *testing.T) {
	content := []byte("sealed recording")
	artifact, err := NewRemoteArtifact(
		ProducerId{1},
		"recording.cast.zst",
		ArtifactDigest(sha256.Sum256(content)),
		int64(len(content)),
		&slowRemoteTargetTestReaderAt{content: content},
	)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	err = artifact.ValidateContext(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func validRemoteArtifactTest() RemoteArtifact {
	content := []byte("sealed recording")
	result, err := NewRemoteArtifact(
		ProducerId{1},
		"recording.cast.zst",
		ArtifactDigest(sha256.Sum256(content)),
		int64(len(content)),
		bytes.NewReader(content),
	)
	if err != nil {
		panic(err)
	}
	return result
}

func remoteTestChecksum(t *testing.T, object remotePublishObject) []byte {
	t.Helper()
	content, err := io.ReadAll(object.Content())
	require.NoError(t, err)
	digest := sha256.Sum256(content)
	return digest[:]
}

func conflictingRemoteArtifactTest(t *testing.T, artifact RemoteArtifact) RemoteArtifact {
	t.Helper()
	content := bytes.Repeat([]byte{'x'}, int(artifact.Size()))
	if bytes.Equal(content, mustReadRemoteTestObject(t, artifact)) {
		content[0]++
	}
	result, err := NewRemoteArtifact(
		artifact.ProducerId(),
		artifact.FileName(),
		ArtifactDigest(sha256.Sum256(content)),
		int64(len(content)),
		bytes.NewReader(content),
	)
	require.NoError(t, err)
	return result
}

func mustReadRemoteTestObject(t *testing.T, object remotePublishObject) []byte {
	t.Helper()
	content, err := io.ReadAll(object.Content())
	require.NoError(t, err)
	return content
}
