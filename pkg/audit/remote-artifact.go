package audit

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"path"

	"github.com/engity-com/bifroest/pkg/errors"
)

const maximumRemoteArtifactFileNameBytes = 255

// ArtifactDigest identifies the exact bytes of a remote artifact.
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
		return errors.Config.Newf("illegal remote artifact digest length: %d", len(text))
	}
	var decoded ArtifactDigest
	if _, err := hex.Decode(decoded[:], text); err != nil {
		return errors.Config.Newf("illegal remote artifact digest: %w", err)
	}
	if decoded.String() != string(text) {
		return errors.Config.Newf("remote artifact digest is not canonical")
	}
	*this = decoded
	return nil
}

// RemoteArtifact describes one byte-exact artifact below its producer's remote
// directory. Content returns a fresh view positioned at offset zero. Targets
// must not retain or close that view and must publish synchronously.
type RemoteArtifact struct {
	producerId ProducerId
	fileName   string
	digest     ArtifactDigest
	size       int64
	content    io.ReaderAt
}

// NewRemoteArtifact constructs an artifact without reading its content.
// Remote target wrappers call ValidateContext immediately before publication.
func NewRemoteArtifact(producerId ProducerId, fileName string, digest ArtifactDigest, size int64, content io.ReaderAt) (RemoteArtifact, error) {
	result := RemoteArtifact{producerId: producerId, fileName: fileName, digest: digest, size: size, content: content}
	if err := result.validateMetadata(context.Background()); err != nil {
		return RemoteArtifact{}, err
	}
	return result, nil
}

func (this RemoteArtifact) Validate() error {
	return this.ValidateContext(context.Background())
}

func (this RemoteArtifact) ValidateContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := this.validateMetadata(ctx); err != nil {
		return err
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, contextReader{context: ctx, reader: this.Content()})
	if err != nil {
		return errors.System.Newf("cannot hash remote artifact content: %w", err)
	}
	if written != this.size {
		return errors.System.Newf("remote artifact content size is %d instead of %d", written, this.size)
	}
	var extra [1]byte
	if err := ctx.Err(); err != nil {
		return err
	}
	read, readErr := this.content.ReadAt(extra[:], this.size)
	if read != 0 || readErr == nil {
		return errors.System.Newf("remote artifact content exceeds declared size %d", this.size)
	}
	if readErr != io.EOF {
		return errors.System.Newf("cannot verify remote artifact content size: %w", readErr)
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), this.digest[:]) != 1 {
		return errors.System.Newf("remote artifact content does not match digest %s", this.digest)
	}
	return nil
}

func (this RemoteArtifact) validateMetadata(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if this.producerId.IsZero() {
		return errors.System.Newf("remote artifact producer ID is empty")
	}
	if err := validateRemoteArtifactFileName(this.fileName); err != nil {
		return err
	}
	if this.digest.IsZero() {
		return errors.System.Newf("remote artifact digest is empty")
	}
	if this.size <= 0 {
		return errors.System.Newf("remote artifact size must be positive")
	}
	if isNilRemoteValue(this.content) {
		return errors.System.Newf("remote artifact content is nil")
	}
	return nil
}

func validateRemoteArtifactFileName(value string) error {
	if len(value) == 0 || len(value) > maximumRemoteArtifactFileNameBytes || path.Base(value) != value || value == "." || value == ".." {
		return errors.Config.Newf("illegal remote artifact file name %q", value)
	}
	for index := range len(value) {
		current := value[index]
		if current >= 'a' && current <= 'z' || current >= 'A' && current <= 'Z' || current >= '0' && current <= '9' || index > 0 && (current == '.' || current == '_' || current == '-') {
			continue
		}
		return errors.Config.Newf("illegal remote artifact file name %q", value)
	}
	return nil
}

func (this RemoteArtifact) ProducerId() ProducerId { return this.producerId }

func (this RemoteArtifact) FileName() string { return this.fileName }

func (this RemoteArtifact) Digest() ArtifactDigest { return this.digest }

func (this RemoteArtifact) Size() int64 { return this.size }

func (this RemoteArtifact) Content() io.ReadSeeker {
	if isNilRemoteValue(this.content) || this.size <= 0 {
		return nil
	}
	return io.NewSectionReader(this.content, 0, this.size)
}

func (this RemoteArtifact) RemotePath() string {
	if this.producerId.IsZero() || validateRemoteArtifactFileName(this.fileName) != nil {
		return ""
	}
	return path.Join(this.producerId.String(), this.fileName)
}

type remotePublishObject interface {
	ProducerId() ProducerId
	FileName() string
	RemotePath() string
	Size() int64
	Content() io.ReadSeeker
}

// RemoteArtifactTarget is an optional capability implemented in addition to
// RemoteTarget. PublishArtifact has the same atomicity and idempotency contract
// as RemoteTarget.Publish and must verify content against ArtifactDigest.
type RemoteArtifactTarget interface {
	PublishArtifact(context.Context, RemoteArtifact) error
}
