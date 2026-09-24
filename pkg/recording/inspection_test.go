package recording

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestInspectDetectsAndVerifiesRecordingFormats(t *testing.T) {
	zstdContainer, cast, zstdSummary, identity := sealedCastZstdTestContent(t, 300)

	plainInspection, err := Inspect(bytes.NewReader(cast), int64(len(cast)), InspectOptions{AllowUntrusted: true})
	require.NoError(t, err)
	require.Equal(t, FormatCast, plainInspection.Format)
	require.NotNil(t, plainInspection.Cast)
	require.Nil(t, plainInspection.CastZstd)
	require.Nil(t, plainInspection.BECast)
	require.False(t, plainInspection.Cast.Trusted)

	zstdInspection, err := Inspect(bytes.NewReader(zstdContainer), int64(len(zstdContainer)), InspectOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, FormatCastZstd, zstdInspection.Format)
	require.NotNil(t, zstdInspection.Cast)
	require.NotNil(t, zstdInspection.CastZstd)
	require.Equal(t, zstdSummary, zstdInspection.CastZstd.Summary)
	require.True(t, zstdInspection.CastZstd.Trusted)

	becastIdentity, header, metadata := castTestValues(t, true)
	recipient, _ := newBECastTestEncryption(t)
	var becastContainer bytes.Buffer
	writer, err := NewBECastWriter(&becastContainer, becastIdentity, recipient, header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Millisecond, OutputStreamTerminal, []byte("encrypted\r\n")))
	exitStatus := uint32(0)
	becastSummary, err := writer.Seal(2*time.Millisecond, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Millisecond)}, &exitStatus)
	require.NoError(t, err)
	becastInspection, err := Inspect(bytes.NewReader(becastContainer.Bytes()), int64(becastContainer.Len()), InspectOptions{AllowUntrusted: true})
	require.NoError(t, err)
	require.Equal(t, FormatBECast, becastInspection.Format)
	require.Nil(t, becastInspection.Cast)
	require.Nil(t, becastInspection.CastZstd)
	require.NotNil(t, becastInspection.BECast)
	require.Nil(t, becastInspection.BECast.Cast)
	require.Equal(t, becastSummary, becastInspection.BECast.Summary)
	require.False(t, becastInspection.BECast.Trusted)
}

func TestInspectRejectsUnsupportedAndUntrustedRecordings(t *testing.T) {
	_, cast, _, _ := sealedCastZstdTestContent(t, 300)
	_, err := Inspect(bytes.NewReader(cast), int64(len(cast)), InspectOptions{})
	require.ErrorContains(t, err, "expected producer ID")
	_, err = Inspect(bytes.NewReader([]byte("unknown")), int64(len("unknown")), InspectOptions{AllowUntrusted: true})
	require.ErrorContains(t, err, "unsupported Recording format")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Inspect(bytes.NewReader(cast), int64(len(cast)), InspectOptions{Context: canceled, AllowUntrusted: true})
	require.ErrorIs(t, err, context.Canceled)
}

func TestInspectEnforcesPlainCastContainerLimit(t *testing.T) {
	_, cast, _, _ := sealedCastZstdTestContent(t, 300)
	size := int64(len(cast))

	inspection, err := Inspect(bytes.NewReader(cast), size, InspectOptions{MaximumContainerBytes: size, AllowUntrusted: true})
	require.NoError(t, err)
	require.Equal(t, FormatCast, inspection.Format)

	_, err = Inspect(bytes.NewReader(cast), size, InspectOptions{MaximumContainerBytes: size - 1, AllowUntrusted: true})
	require.ErrorContains(t, err, "outside the supported range")
	require.True(t, bferrors.System.IsErr(err))

	_, err = Inspect(bytes.NewReader(cast), size, InspectOptions{MaximumContainerBytes: -1, AllowUntrusted: true})
	require.ErrorContains(t, err, "must be positive")
	require.True(t, bferrors.Config.IsErr(err))

	_, err = Inspect(bytes.NewReader(cast), DefaultMaximumCastBytes+1, InspectOptions{AllowUntrusted: true})
	require.ErrorContains(t, err, "outside the supported range")
	require.True(t, bferrors.System.IsErr(err))
}

func TestInspectNativeModesAndMagic(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	recipient, _ := newBECastTestEncryption(t)
	for _, test := range []struct {
		name      string
		recipient bool
		format    Format
	}{
		{"clear", false, FormatBcast},
		{"encrypted", true, FormatBECastCBOR},
	} {
		t.Run(test.name, func(t *testing.T) {
			var container bytes.Buffer
			var writerRecipient = recipient
			if !test.recipient {
				writerRecipient = nil
			}
			writer, err := NewNativeRecordingWriter(&container, identity, writerRecipient, header, metadata, 300, NativeRecordingWriterLimits{})
			require.NoError(t, err)
			require.NoError(t, writer.WriteOutput(time.Millisecond, OutputStreamTerminal, []byte("private output")))
			exit := uint32(0)
			_, err = writer.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, &exit)
			require.NoError(t, err)
			contents := container.Bytes()
			format, err := DetectFormat(bytes.NewReader(contents), int64(len(contents)))
			require.NoError(t, err)
			require.Equal(t, test.format, format)
			inspection, err := Inspect(bytes.NewReader(contents), int64(len(contents)), InspectOptions{ExpectedProducerId: identity.ProducerId()})
			require.NoError(t, err)
			require.Equal(t, test.format, inspection.Format)
			require.NotNil(t, inspection.Native)
			require.True(t, inspection.Native.Trusted)
			require.Nil(t, inspection.Cast)
			_, err = Inspect(bytes.NewReader(contents), int64(len(contents)), InspectOptions{ExpectedProducerId: identity.ProducerId(), MaximumContainerBytes: int64(len(contents) - 1)})
			require.Error(t, err)
			corrupt := bytes.Clone(contents)
			corrupt[len(corrupt)-1] ^= 1
			_, err = Inspect(bytes.NewReader(corrupt), int64(len(corrupt)), InspectOptions{AllowUntrusted: true})
			require.Error(t, err)
		})
	}
}
