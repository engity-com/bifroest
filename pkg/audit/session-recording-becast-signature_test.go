package audit

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestSessionRecordingBECastHeaderSignVerifyAndRejectTampering(t *testing.T) {
	identity := newSessionRecordingBECastTestIdentity(t)
	header, err := identity.NewSessionRecordingBECastHeader(1, 2, 3, 4, sessionRecordingBECastTestRecordingId(), identity.Fingerprint())
	require.NoError(t, err)
	require.Equal(t, identity.ProducerId(), header.ProducerId)
	require.Equal(t, identity.PublicKey().Marshal(), header.PublicKey)

	publicKey, err := VerifySessionRecordingBECastHeader(header)
	require.NoError(t, err)
	require.Equal(t, identity.PublicKey().Marshal(), publicKey.Marshal())

	header.CastVersion++
	_, err = VerifySessionRecordingBECastHeader(header)
	require.ErrorContains(t, err, "illegal session recording signature")
}

func TestSessionRecordingBECastChunkSignVerifyAndRejectTampering(t *testing.T) {
	identity := newSessionRecordingBECastTestIdentity(t)
	chunk, err := identity.NewSessionRecordingBECastChunk(validSessionRecordingBECastChunk())
	require.NoError(t, err)
	require.Equal(t, identity.ProducerId(), chunk.ProducerId)
	require.NoError(t, VerifySessionRecordingBECastChunk(identity.PublicKey(), chunk))

	chunk.PlaintextOffset++
	require.ErrorContains(t, VerifySessionRecordingBECastChunk(identity.PublicKey(), chunk), "illegal session recording signature")
}

func TestSessionRecordingBECastSealSignVerifyAndRejectTampering(t *testing.T) {
	identity := newSessionRecordingBECastTestIdentity(t)
	seal, err := identity.NewSessionRecordingBECastSeal(validSessionRecordingBECastSeal())
	require.NoError(t, err)
	require.Equal(t, identity.ProducerId(), seal.ProducerId)
	require.NoError(t, VerifySessionRecordingBECastSeal(identity.PublicKey(), seal))

	seal.CastBytes++
	require.ErrorContains(t, VerifySessionRecordingBECastSeal(identity.PublicKey(), seal), "illegal session recording signature")
}

func TestSessionRecordingBECastHeadSignVerifyAndRejectTampering(t *testing.T) {
	identity := newSessionRecordingBECastTestIdentity(t)
	head, err := identity.NewSessionRecordingBECastHead(validSessionRecordingBECastHead())
	require.NoError(t, err)
	require.Equal(t, identity.ProducerId(), head.ProducerId)
	require.NoError(t, VerifySessionRecordingBECastHead(identity.PublicKey(), head))

	head.PrefixBytes++
	require.ErrorContains(t, VerifySessionRecordingBECastHead(identity.PublicKey(), head), "illegal session recording signature")
}

func TestSessionRecordingBECastHeaderRejectsInvalidRecipientFingerprint(t *testing.T) {
	identity := newSessionRecordingBECastTestIdentity(t)
	for _, fingerprint := range []string{
		"",
		"SHA256:" + strings.Repeat("A", 42),
		"SHA256:" + strings.Repeat("*", 43),
		"SHA256:" + strings.Repeat("A", 43) + "=",
	} {
		t.Run(fingerprint, func(t *testing.T) {
			_, err := identity.NewSessionRecordingBECastHeader(1, 2, 3, 4, sessionRecordingBECastTestRecordingId(), fingerprint)
			require.ErrorContains(t, err, "recipient fingerprint")
		})
	}
}

func TestSessionRecordingBECastRejectsUnalignedContentHashBytes(t *testing.T) {
	identity := newSessionRecordingBECastTestIdentity(t)
	chunk := validSessionRecordingBECastChunk()
	chunk.ContentHashBytes = 65
	_, err := identity.NewSessionRecordingBECastChunk(chunk)
	require.ErrorContains(t, err, "not aligned to 64 bytes")

	head := validSessionRecordingBECastHead()
	head.ContentHashBytes = 65
	_, err = identity.NewSessionRecordingBECastHead(head)
	require.ErrorContains(t, err, "not aligned to 64 bytes")
}

func TestSessionRecordingBECastFinalChunkContentHashSentinel(t *testing.T) {
	identity := newSessionRecordingBECastTestIdentity(t)
	chunk := validSessionRecordingBECastChunk()
	chunk.ContentHashBytes = 0
	signed, err := identity.NewSessionRecordingBECastChunk(chunk)
	require.NoError(t, err)
	require.NoError(t, VerifySessionRecordingBECastChunk(identity.PublicKey(), signed))

	chunk.ContentHashState = SessionRecordingHash{}
	_, err = identity.NewSessionRecordingBECastChunk(chunk)
	require.ErrorContains(t, err, "empty content hash sentinel")
}

func TestSessionRecordingBECastAcceptsOpaqueZeroContentHashState(t *testing.T) {
	identity := newSessionRecordingBECastTestIdentity(t)
	chunk := validSessionRecordingBECastChunk()
	chunk.ContentHashState = SessionRecordingHash{}
	_, err := identity.NewSessionRecordingBECastChunk(chunk)
	require.NoError(t, err)

	head := validSessionRecordingBECastHead()
	head.ContentHashState = SessionRecordingHash{}
	_, err = identity.NewSessionRecordingBECastHead(head)
	require.NoError(t, err)
}

func newSessionRecordingBECastTestIdentity(t *testing.T) *Identity {
	t.Helper()
	privateKey, err := auditIdentityKeyRequirement.GenerateKey(nil)
	require.NoError(t, err)
	identity, err := NewIdentity(privateKey)
	require.NoError(t, err)
	return identity
}

func sessionRecordingBECastTestRecordingId() uuid.UUID {
	return uuid.MustParse("fd70203b-ea19-4288-8ec2-577b623e92d0")
}

func validSessionRecordingBECastChunk() SessionRecordingBECastChunk {
	return SessionRecordingBECastChunk{
		FormatVersion:    1,
		RecordingId:      sessionRecordingBECastTestRecordingId(),
		Sequence:         1,
		PreviousUnitHash: SessionRecordingHash{1},
		PlaintextLength:  128,
		CiphertextLength: 144,
		CiphertextHash:   SessionRecordingHash{2},
		ContentHashState: SessionRecordingHash{3},
		ContentHashBytes: 128,
	}
}

func validSessionRecordingBECastSeal() SessionRecordingBECastSeal {
	return SessionRecordingBECastSeal{
		FormatVersion:        1,
		RecordingId:          sessionRecordingBECastTestRecordingId(),
		Status:               1,
		ChunkCount:           2,
		CastBytes:            256,
		CiphertextBytes:      288,
		PrefixBytes:          512,
		HeaderUnitHash:       SessionRecordingHash{1},
		LastChunkUnitHash:    SessionRecordingHash{2},
		CastContentDigest:    SessionRecordingHash{3},
		CiphertextStreamHash: SessionRecordingHash{4},
	}
}

func validSessionRecordingBECastHead() SessionRecordingBECastHead {
	return SessionRecordingBECastHead{
		FormatVersion:    1,
		RecordingId:      sessionRecordingBECastTestRecordingId(),
		ChunkCount:       2,
		PrefixBytes:      512,
		LastUnitHash:     SessionRecordingHash{1},
		ContentHashState: SessionRecordingHash{2},
		ContentHashBytes: 128,
	}
}
