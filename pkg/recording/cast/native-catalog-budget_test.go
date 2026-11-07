package cast

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func TestNativeCatalogDecodedBudgetIsCumulativeAndNeverFallsBackAtZero(t *testing.T) {
	budget := &nativeCatalogDecodeBudget{maximum: 16}
	first, err := budget.payloadLimits(8)
	require.NoError(t, err)
	require.Equal(t, 8, first.MaxDecoded)
	_, err = budget.payloadLimits(9)
	require.ErrorIs(t, err, ErrNativeCatalogDecodedBudget)
	require.EqualValues(t, 8, budget.used, "a rejected chunk must not be decoded")
	_, err = budget.payloadLimits(8)
	require.NoError(t, err)
	_, err = budget.payloadLimits(1)
	require.ErrorIs(t, err, ErrNativeCatalogDecodedBudget)
	require.EqualValues(t, 16, budget.peak)
	budget.beginPass()
	_, err = budget.payloadLimits(16)
	require.NoError(t, err, "the fixed second verification pass has its own same-sized allowance")
	require.EqualValues(t, 16, budget.peak)
	_, _, err = VerifyNativeRecordingCatalog(bytes.NewReader(nil), 0, false, 0, NativeRecordingVerifyOptions{})
	require.ErrorIs(t, err, ErrNativeCatalogDecodedBudget)
	var ordinary *nativeCatalogDecodeBudget
	limits, err := ordinary.payloadLimits(nativeformat.MaxRecordingDecodedChunk)
	require.NoError(t, err)
	require.Equal(t, nativeRecordingPayloadLimits, limits, "ordinary CLI/native verification defaults remain unchanged")
}

func TestNativeCatalogDecodedBudgetCapsActualZstdExpansionBeforeAllocation(t *testing.T) {
	// An authenticated length claim must not let a larger actual frame decode
	// first and fail only at the later len(decoded) comparison.
	stored, err := nativeformat.EncodeStoredPayload(bytes.Repeat([]byte("x"), 4096), nil, nativeRecordingPayloadLimits)
	require.NoError(t, err)
	budget := &nativeCatalogDecodeBudget{maximum: 32}
	limits, err := budget.payloadLimits(16) // Dishonest declared length.
	require.NoError(t, err)
	require.Equal(t, 16, limits.MaxDecoded)
	decoded, err := nativeformat.DecodeStoredPayload(stored, nil, "", limits)
	require.ErrorContains(t, err, "header metadata")
	require.Nil(t, decoded, "the actual Zstd content size must fail before plaintext allocation/decompression")
}
