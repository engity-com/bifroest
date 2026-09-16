package recording

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/errors"
)

// ArtifactDigest identifies the exact bytes of a sealed recording container.
// It is distinct from CastDigest, which identifies the canonical Cast content.
type ArtifactDigest [sha256.Size]byte

func (this ArtifactDigest) String() string {
	return hex.EncodeToString(this[:])
}

func (this ArtifactDigest) IsZero() bool {
	return this == ArtifactDigest{}
}

func (this ArtifactDigest) MarshalText() ([]byte, error) {
	return []byte(this.String()), nil
}

func (this *ArtifactDigest) UnmarshalText(text []byte) error {
	if len(text) != hex.EncodedLen(len(this)) {
		return errors.Config.Newf("illegal recording artifact digest length: %d", len(text))
	}
	var decoded ArtifactDigest
	if _, err := hex.Decode(decoded[:], text); err != nil {
		return errors.Config.Newf("illegal recording artifact digest: %w", err)
	}
	if decoded.String() != string(text) {
		return errors.Config.Newf("recording artifact digest is not canonical")
	}
	*this = decoded
	return nil
}

// LocalSealedArtifact is a signature-verified, read-only handle to one local recording.
// ArtifactDigest describes the bytes observed while the handle was opened. Callers must
// keep repository storage private from processes that can modify read-only files.
// The caller owns the handle and must close it.
type LocalSealedArtifact[Summary any] struct {
	mutex          sync.RWMutex
	file           *os.File
	recordingId    Id
	producerId     audit.ProducerId
	fileName       string
	size           int64
	artifactDigest ArtifactDigest
	summary        Summary
}

func (this *LocalSealedArtifact[Summary]) RecordingId() Id {
	if this == nil {
		return Id{}
	}
	return this.recordingId
}

func (this *LocalSealedArtifact[Summary]) ProducerId() audit.ProducerId {
	if this == nil {
		return audit.ProducerId{}
	}
	return this.producerId
}

func (this *LocalSealedArtifact[Summary]) FileName() string {
	if this == nil {
		return ""
	}
	return this.fileName
}

func (this *LocalSealedArtifact[Summary]) Size() int64 {
	if this == nil {
		return 0
	}
	return this.size
}

func (this *LocalSealedArtifact[Summary]) ArtifactDigest() ArtifactDigest {
	if this == nil {
		return ArtifactDigest{}
	}
	return this.artifactDigest
}

func (this *LocalSealedArtifact[Summary]) Summary() Summary {
	if this == nil {
		var zero Summary
		return zero
	}
	return this.summary
}

func (this *LocalSealedArtifact[Summary]) Reader() io.Reader {
	if this == nil {
		return bytes.NewReader(nil)
	}
	return io.NewSectionReader(this, 0, this.size)
}

func (this *LocalSealedArtifact[Summary]) ReadAt(target []byte, offset int64) (int, error) {
	if this == nil {
		return 0, errors.System.Newf("nil sealed recording artifact")
	}
	this.mutex.RLock()
	defer this.mutex.RUnlock()
	if this.file == nil {
		return 0, errors.System.Newf("sealed recording artifact is closed")
	}
	return io.NewSectionReader(this.file, 0, this.size).ReadAt(target, offset)
}

func (this *LocalSealedArtifact[Summary]) Close() error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.file == nil {
		return nil
	}
	file := this.file
	this.file = nil
	return file.Close()
}
