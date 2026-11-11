package cast

import (
	"errors"
	"fmt"
	"io"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

var ErrNativeCatalogDecodedBudget = errors.New("native recording catalog decoded budget exceeded")
var ErrNativeCatalogCastBudget = errors.New("native recording catalog canonical Cast budget exceeded")

// This optional ledger is set only by the bounded catalog verifier. Nil keeps
// every ordinary native/CLI verification path's existing defaults unchanged.
type nativeCatalogDecodeBudget struct {
	maximum uint64
	used    uint64
	peak    uint64
}

func (budget *nativeCatalogDecodeBudget) beginPass() {
	if budget != nil {
		budget.used = 0
	}
}

func (budget *nativeCatalogDecodeBudget) payloadLimits(decodedLength uint32) (nativeformat.PayloadLimits, error) {
	limits := nativeRecordingPayloadLimits
	if budget == nil {
		return limits, nil
	}
	length := uint64(decodedLength)
	if length == 0 || length > nativeformat.MaxRecordingDecodedChunk || budget.used > budget.maximum || length > budget.maximum-budget.used {
		return limits, ErrNativeCatalogDecodedBudget
	}
	budget.used += length
	budget.peak = max(budget.peak, budget.used)
	// DecodeZstdFrame checks the frame's actual content size against MaxDecoded
	// before allocation/decompression. A dishonest smaller DecodedLength cannot
	// make the decoder expand beyond this allowance before failing validation.
	limits.MaxDecoded = int(length)
	return limits, nil
}

// VerifyNativeRecordingCatalog accepts no decryption keys. It verifies clear
// artifacts fully, encrypted artifacts only at the existing outer scope, and
// applies an independent cumulative CBOR decode bound before every chunk decode.
// Its return shape leaves the established native verification result untouched.
func VerifyNativeRecordingCatalog(source io.ReaderAt, size int64, encrypted bool, maximumDecodedBytes uint64, options NativeRecordingVerifyOptions) (*NativeRecordingVerification, uint64, error) {
	if maximumDecodedBytes == 0 {
		return nil, 0, fmt.Errorf("%w: zero allowance", ErrNativeCatalogDecodedBudget)
	}
	budget := &nativeCatalogDecodeBudget{maximum: maximumDecodedBytes}
	options.catalogBudget = budget
	var verification *NativeRecordingVerification
	var err error
	if encrypted {
		verification, err = VerifyNativeRecordingOuter(source, size, options)
	} else {
		verification, err = VerifyNativeRecordingFull(source, size, nil, options)
	}
	if err != nil {
		return nil, 0, err
	}
	return verification, budget.peak, nil
}
