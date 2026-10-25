package recording

import (
	"github.com/engity-com/bifroest/pkg/recording/cast"
	"io"
	"time"
)

type CastVerifyOptions = cast.CastVerifyOptions
type CastVerification = cast.CastVerification

func VerifyCast(input io.Reader, options CastVerifyOptions) (*CastVerification, error) {
	return cast.VerifyCast(input, options)
}
func decodeCastHeader(payload []byte, target *CastHeader) error {
	return cast.DecodeHeader(payload, target)
}
func decodeCastEvent(payload []byte) (time.Duration, string, string, error) {
	return cast.DecodeEvent(payload)
}

func validateResizeEvent(value string) error         { return cast.ValidateResizeEvent(value) }
func rejectDuplicateJSONFields(payload []byte) error { return cast.RejectDuplicateJSONFields(payload) }
