package recording

import (
	"github.com/engity-com/bifroest/pkg/recording/cast"
	"io"
)

const (
	NativeEventSetup             = cast.NativeEventSetup
	NativeEventOutput            = cast.NativeEventOutput
	NativeEventResize            = cast.NativeEventResize
	NativeEventMarker            = cast.NativeEventMarker
	NativeEventPaddingCheckpoint = cast.NativeEventPaddingCheckpoint
	NativeEventResult            = cast.NativeEventResult
)

type NativeCastEvent = cast.NativeCastEvent

func EncodeNativeRecordingEvents(events []NativeCastEvent) ([]byte, error) {
	return cast.EncodeNativeRecordingEvents(events)
}
func decodeNativeRecordingEvents(data []byte) ([]NativeCastEvent, error) {
	return cast.DecodeNativeRecordingEvents(data)
}
func RenderNativeRecordingCast(groups [][]byte, header NativeRecordingHeader, seal NativeRecordingSeal, maximum int64) ([]byte, error) {
	return cast.RenderNativeRecordingCast(groups, header, seal, maximum)
}

func castOutputChunkEnd(data []byte, offset int) int { return cast.OutputChunkEnd(data, offset) }
func nativeStatusNumber(value CastStatus) uint8      { return cast.NativeStatusNumber(value) }

type nativeCastRenderer struct {
	inner *cast.ProvisionalNativeRenderer
}

func newNativeCastRenderer(out io.Writer, h NativeRecordingHeader, s NativeRecordingSeal, maximum int64) (*nativeCastRenderer, error) {
	inner, err := cast.NewProvisionalNativeRenderer(out, h, s, maximum)
	if err != nil {
		return nil, err
	}
	return &nativeCastRenderer{inner}, nil
}
func (r *nativeCastRenderer) consumeGroup(events []NativeCastEvent) error {
	return r.inner.ConsumeGroup(events)
}
