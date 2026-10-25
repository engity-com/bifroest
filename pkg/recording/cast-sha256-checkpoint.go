package recording

import (
	"github.com/engity-com/bifroest/pkg/recording/cast"
	"hash"
)

type castSha256Checkpoint = cast.Sha256Checkpoint

func padCastForSha256Checkpoint(w *CastWriter) (castSha256Checkpoint, error) {
	return cast.PadForSha256Checkpoint(w)
}
func resumeCastSha256(v castSha256Checkpoint) (hash.Hash, error) { return cast.ResumeSha256(v) }
