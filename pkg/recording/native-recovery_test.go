package recording

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

type nativeRecoveryFixture struct {
	container                          []byte
	head                               []byte
	headEnd, continuationEnd, finalEnd int64
	identity                           *audit.Identity
	recipient                          *bfcrypto.AgeSshRecipient
	identities                         *bfcrypto.AgeSshIdentities
	started                            time.Time
}

type nativeRecoverySyncFailure struct {
	*os.File
	fail bool
}

func (f *nativeRecoverySyncFailure) Sync() error {
	if f.fail {
		f.fail = false
		return errors.New("injected native recovery sync failure")
	}
	return f.File.Sync()
}

func TestNativeRecordingRecoveryInterruptedSealCommit(t *testing.T) {
	fixture := newNativeRecoveryFixture(t, true)
	file := nativeRecoveryTestFile(t, fixture.container[:fixture.finalEnd])
	wrapper := &nativeRecoverySyncFailure{File: file, fail: true}
	options := NativeRecordingVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}
	_, err := RecoverNativeRecording(wrapper, fixture.identity, fixture.recipient, fixture.head, fixture.started.Add(2*time.Second), options)
	require.ErrorContains(t, err, "injected native recovery sync failure")
	length, err := file.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	require.Greater(t, length, fixture.finalEnd, "state-0 seal body remains uncommitted")
	_, err = VerifyNativeRecordingOuter(file, length, options)
	require.Error(t, err)
	recovered, err := RecoverNativeRecording(wrapper, fixture.identity, fixture.recipient, fixture.head, fixture.started.Add(2*time.Second), options)
	require.NoError(t, err)
	require.True(t, recovered.Truncated)
	require.Equal(t, uint8(1), recovered.Verification.Seal.Status)
	length, err = file.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	actual, err := io.ReadAll(io.NewSectionReader(file, 0, length))
	require.NoError(t, err)
	require.Equal(t, fixture.container, actual)
}

func TestNativeRecordingRecoveryWithoutHeadOnlySealsCommittedFinal(t *testing.T) {
	fixture := newNativeRecoveryFixture(t, true)
	options := NativeRecordingVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}
	file := nativeRecoveryTestFile(t, fixture.container[:fixture.finalEnd])
	result, err := RecoverNativeRecording(file, fixture.identity, fixture.recipient, nil, fixture.started.Add(2*time.Second), options)
	require.NoError(t, err)
	require.True(t, result.Finalized)
	require.Equal(t, uint8(1), result.Verification.Seal.Status)
	length, err := file.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	actual, err := io.ReadAll(io.NewSectionReader(file, 0, length))
	require.NoError(t, err)
	require.Equal(t, fixture.container, actual)

	continuation := nativeRecoveryTestFile(t, fixture.container[:fixture.continuationEnd])
	_, err = RecoverNativeRecording(continuation, fixture.identity, fixture.recipient, nil, fixture.started.Add(2*time.Second), options)
	require.ErrorContains(t, err, "no committed final chunk")
	length, err = continuation.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	require.Equal(t, fixture.continuationEnd, length)

	stateZero := bytes.Clone(fixture.container[fixture.continuationEnd:fixture.finalEnd])
	stateZero[5] = 0
	withTail := nativeRecoveryTestFile(t, append(bytes.Clone(fixture.container[:fixture.continuationEnd]), stateZero...))
	_, err = RecoverNativeRecording(withTail, fixture.identity, fixture.recipient, nil, fixture.started.Add(2*time.Second), options)
	require.ErrorContains(t, err, "uncommitted native tail")
}

func TestNativeRecordingRecoveryClampsClockSkewToSignedElapsed(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		fixture := newNativeRecoveryFixture(t, encrypted)
		file := nativeRecoveryTestFile(t, fixture.container[:fixture.continuationEnd])
		options := NativeRecordingVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}
		result, err := RecoverNativeRecording(file, fixture.identity, fixture.recipient, fixture.head, fixture.started.Add(100*time.Millisecond), options)
		require.NoError(t, err)
		want := fixture.started.Add(250 * time.Millisecond)
		require.Equal(t, nativeformat.TimestampOf(want), result.Verification.Seal.EndedAt)
		length, err := file.Seek(0, io.SeekEnd)
		require.NoError(t, err)
		_, err = VerifyNativeRecordingFull(file, length, fixture.identities, options)
		require.NoError(t, err)

		for _, recoveredAt := range []time.Time{
			fixture.started.Add(100 * time.Millisecond).In(time.FixedZone("skewed", 3600)),
			fixture.started.Add(maximumEventElapsed + time.Nanosecond),
		} {
			unmodified := nativeRecoveryTestFile(t, fixture.container[:fixture.continuationEnd])
			_, err := RecoverNativeRecording(unmodified, fixture.identity, fixture.recipient, fixture.head, recoveredAt, options)
			require.Error(t, err)
			after, err := io.ReadAll(io.NewSectionReader(unmodified, 0, fixture.continuationEnd))
			require.NoError(t, err)
			require.Equal(t, fixture.container[:fixture.continuationEnd], after)
		}
	}
}

func newNativeRecoveryFixture(t *testing.T, encrypted bool) nativeRecoveryFixture {
	t.Helper()
	identity, header, metadata := castTestValues(t, true)
	var recipient *bfcrypto.AgeSshRecipient
	var identities *bfcrypto.AgeSshIdentities
	if encrypted {
		recipient, identities = newBECastTestEncryption(t)
	}
	var container bytes.Buffer
	writer, err := NewNativeRecordingWriter(&container, identity, recipient, header, metadata, 0, NativeRecordingWriterLimits{})
	require.NoError(t, err)
	head, err := writer.Checkpoint()
	require.NoError(t, err)
	headEnd := int64(container.Len())
	require.NoError(t, writer.WriteOutput(250*time.Millisecond, OutputStreamTerminal, []byte("committed output")))
	require.NoError(t, writer.Flush())
	continuationEnd := int64(container.Len())
	exit := uint32(0)
	_, err = writer.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, &exit)
	require.NoError(t, err)
	reader := bytes.NewReader(container.Bytes())
	_, offset, _, err := nativeformat.ReadUnitAt(reader, int64(len(nativeformat.RecordingMagic)), int64(container.Len()), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	for range 3 {
		_, offset, _, err = nativeformat.ReadUnitAt(reader, offset, int64(container.Len()), nativeformat.MaxRecordingChunkPayload)
		require.NoError(t, err)
	}
	require.Greater(t, offset, continuationEnd)
	return nativeRecoveryFixture{bytes.Clone(container.Bytes()), head, headEnd, continuationEnd, offset, identity, recipient, identities, metadata.StartedAt}
}

func nativeRecoveryTestFile(t *testing.T, input []byte) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "native-recovery-*.bcast")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	_, err = file.Write(input)
	require.NoError(t, err)
	require.NoError(t, file.Sync())
	return file
}

func TestNativeRecordingRecoveryCrashMatrix(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		fixture := newNativeRecoveryFixture(t, encrypted)
		options := NativeRecordingVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}
		cases := []struct {
			name                               string
			data                               []byte
			sealed, truncated, completed, fail bool
		}{
			{"head", bytes.Clone(fixture.container[:fixture.headEnd]), false, false, false, false},
			{"committed continuation", bytes.Clone(fixture.container[:fixture.continuationEnd]), false, false, false, false},
			{"committed final without seal", bytes.Clone(fixture.container[:fixture.finalEnd]), false, false, true, false},
			{"already sealed", bytes.Clone(fixture.container), true, false, true, false},
			{"lost checkpoint", bytes.Clone(fixture.container[:fixture.headEnd-1]), false, false, false, true},
		}
		uncommittedSeal := bytes.Clone(fixture.container[fixture.finalEnd:])
		uncommittedSeal[5] = 0
		cases = append(cases, struct {
			name                               string
			data                               []byte
			sealed, truncated, completed, fail bool
		}{"committed final and uncommitted seal", append(bytes.Clone(fixture.container[:fixture.finalEnd]), uncommittedSeal...), false, true, true, false})
		uncommitted := bytes.Clone(fixture.container[fixture.headEnd:fixture.continuationEnd])
		uncommitted[5] = 0
		cases = append(cases, struct {
			name                               string
			data                               []byte
			sealed, truncated, completed, fail bool
		}{"uncommitted tail", append(bytes.Clone(fixture.container[:fixture.headEnd]), uncommitted...), false, true, false, false})
		uncommittedFinal := bytes.Clone(fixture.container[fixture.continuationEnd:fixture.finalEnd])
		uncommittedFinal[5] = 0
		cases = append(cases, struct {
			name                               string
			data                               []byte
			sealed, truncated, completed, fail bool
		}{"committed continuation and uncommitted final", append(bytes.Clone(fixture.container[:fixture.continuationEnd]), uncommittedFinal...), false, true, false, false})
		corrupt := bytes.Clone(fixture.container[:fixture.continuationEnd])
		corrupt[fixture.headEnd+6] ^= 1
		cases = append(cases, struct {
			name                               string
			data                               []byte
			sealed, truncated, completed, fail bool
		}{"committed invalid chunk", corrupt, false, false, false, true})
		corruptFinal := bytes.Clone(fixture.container[:fixture.finalEnd])
		corruptFinal[fixture.continuationEnd+6] ^= 1
		cases = append(cases, struct {
			name                               string
			data                               []byte
			sealed, truncated, completed, fail bool
		}{"committed invalid final", corruptFinal, false, false, false, true})
		cases = append(cases, struct {
			name                               string
			data                               []byte
			sealed, truncated, completed, fail bool
		}{"partial frame prefix", append(bytes.Clone(fixture.container[:fixture.headEnd]), 2, 0, 0), false, true, false, false})
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				file := nativeRecoveryTestFile(t, tc.data)
				result, err := RecoverNativeRecording(file, fixture.identity, fixture.recipient, fixture.head, fixture.started.Add(2*time.Second), options)
				if tc.fail {
					require.Error(t, err)
					require.Nil(t, result)
					actual, readErr := io.ReadAll(io.NewSectionReader(file, 0, int64(len(tc.data))))
					require.NoError(t, readErr)
					require.Equal(t, tc.data, actual)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.sealed, result.AlreadySealed)
				require.Equal(t, tc.truncated, result.Truncated)
				require.Equal(t, !tc.sealed, result.Finalized)
				length, err := file.Seek(0, io.SeekEnd)
				require.NoError(t, err)
				verified, err := VerifyNativeRecordingOuter(file, length, options)
				require.NoError(t, err)
				require.Equal(t, verified.Seal, result.Verification.Seal)
				status := uint8(3)
				if tc.completed {
					status = 1
					require.Equal(t, nativeformat.TimestampOf(fixture.started.Add(time.Second)), verified.Seal.EndedAt)
				}
				require.Equal(t, status, verified.Seal.Status)
				if tc.name == "committed final without seal" || tc.name == "committed final and uncommitted seal" {
					all, readErr := io.ReadAll(io.NewSectionReader(file, 0, length))
					require.NoError(t, readErr)
					require.Equal(t, fixture.container, all, "recovery may only append the original signed seal")
				}
				_, err = VerifyNativeRecordingFull(file, length, fixture.identities, options)
				require.NoError(t, err)
				if !tc.completed {
					offset := int64(len(nativeformat.RecordingMagic))
					_, offset, _, err = nativeformat.ReadUnitAt(file, offset, length, nativeformat.MaxMetadataPayload)
					require.NoError(t, err)
					var finalChunk nativeRecordingChunk
					for range verified.Seal.ChunkCount {
						unit, next, tail, readErr := nativeformat.ReadUnitAt(file, offset, length, nativeformat.MaxRecordingChunkPayload)
						require.NoError(t, readErr)
						require.False(t, tail)
						finalChunk, readErr = nativeformat.Unmarshal[nativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
						require.NoError(t, readErr)
						offset = next
					}
					decoded, readErr := nativeformat.DecodeStoredPayload(finalChunk.StoredPayload, fixture.identities, verified.Header.Recipient, nativeRecordingPayloadLimits)
					require.NoError(t, readErr)
					events, readErr := decodeNativeRecordingEvents(decoded)
					require.NoError(t, readErr)
					require.Len(t, events, 1)
					wantElapsed := time.Duration(0)
					if tc.name == "committed continuation" || tc.name == "committed continuation and uncommitted final" {
						wantElapsed = 250 * time.Millisecond
					}
					require.Equal(t, wantElapsed, events[0].Elapsed)
				}
			})
		}
		t.Run("corrupt signed head", func(t *testing.T) {
			file := nativeRecoveryTestFile(t, fixture.container[:fixture.continuationEnd])
			before := bytes.Clone(fixture.container[:fixture.continuationEnd])
			badHead := bytes.Clone(fixture.head)
			badHead[len(badHead)-1] ^= 1
			_, err := RecoverNativeRecording(file, fixture.identity, fixture.recipient, badHead, fixture.started.Add(2*time.Second), options)
			require.Error(t, err)
			actual, err := io.ReadAll(io.NewSectionReader(file, 0, int64(len(before))))
			require.NoError(t, err)
			require.Equal(t, before, actual)
		})
	}
}
