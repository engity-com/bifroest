package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	bfssh "github.com/engity-com/bifroest/pkg/ssh"
)

const (
	remoteDeliveryDestinationFingerprintDomain = "BIFROEST-AUDIT-REMOTE-DESTINATION/v1\x00"
	remoteTargetCleanupTimeout                 = 5 * time.Second
)

// SegmentHash is the domain-separated hash bound to a sealed segment's file
// name. It is not a plain SHA-256 checksum of the file contents.
type SegmentHash [sha256.Size]byte

func (this SegmentHash) String() string {
	return hex.EncodeToString(this[:])
}

func (this SegmentHash) IsZero() bool {
	return this == SegmentHash{}
}

func (this SegmentHash) MarshalText() ([]byte, error) {
	return []byte(this.String()), nil
}

func (this *SegmentHash) UnmarshalText(text []byte) error {
	if len(text) != hex.EncodedLen(len(this)) {
		return errors.Config.Newf("illegal audit segment hash length: %d", len(text))
	}
	var decoded SegmentHash
	if _, err := hex.Decode(decoded[:], text); err != nil {
		return errors.Config.Newf("illegal audit segment hash: %w", err)
	}
	*this = decoded
	return nil
}

// SealedSegment describes one immutable, locally verified native audit segment.
// Content returns a fresh view positioned at offset zero. Targets must not
// retain or close that view and must publish synchronously before returning.
type SealedSegment struct {
	producerId ProducerId
	sequence   uint64
	hash       SegmentHash
	size       int64
	content    io.ReaderAt
	encrypted  bool
}

func (this SealedSegment) Validate() error {
	return this.ValidateContext(context.Background())
}

func (this SealedSegment) ValidateContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if this.producerId.IsZero() {
		return errors.System.Newf("sealed audit segment producer ID is empty")
	}
	if this.sequence == 0 {
		return errors.System.Newf("sealed audit segment sequence is empty")
	}
	if this.hash.IsZero() {
		return errors.System.Newf("sealed audit segment hash is empty")
	}
	if this.size <= 0 {
		return errors.System.Newf("sealed audit segment size must be positive")
	}
	if isNilRemoteValue(this.content) {
		return errors.System.Newf("sealed audit segment content is nil")
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(nativeAuditSegmentHashDomain))
	written, err := io.Copy(hasher, contextReader{context: ctx, reader: io.NewSectionReader(this.content, 0, this.size)})
	if err != nil {
		return errors.System.Newf("cannot hash sealed audit segment content: %w", err)
	}
	if written != this.size {
		return errors.System.Newf("sealed audit segment content size is %d instead of %d", written, this.size)
	}
	var extra [1]byte
	if err := ctx.Err(); err != nil {
		return err
	}
	read, readErr := this.content.ReadAt(extra[:], this.size)
	if read != 0 || readErr == nil {
		return errors.System.Newf("sealed audit segment content exceeds declared size %d", this.size)
	}
	if readErr != io.EOF {
		return errors.System.Newf("cannot verify sealed audit segment content size: %w", readErr)
	}
	var actualHash SegmentHash
	copy(actualHash[:], hasher.Sum(nil))
	if actualHash != this.hash {
		return errors.System.Newf("sealed audit segment content does not match hash %s", this.hash)
	}
	return nil
}

func newSealedSegment(producerId ProducerId, sequence uint64, hash SegmentHash, size int64, content io.ReaderAt) (SealedSegment, error) {
	return newSealedSegmentContext(context.Background(), producerId, sequence, hash, size, content)
}

func newSealedSegmentContext(ctx context.Context, producerId ProducerId, sequence uint64, hash SegmentHash, size int64, content io.ReaderAt) (SealedSegment, error) {
	result := SealedSegment{producerId: producerId, sequence: sequence, hash: hash, size: size, content: content}
	if err := result.ValidateContext(ctx); err != nil {
		return SealedSegment{}, err
	}
	return result, nil
}

func (this SealedSegment) ProducerId() ProducerId {
	return this.producerId
}

func (this SealedSegment) Sequence() uint64 {
	return this.sequence
}

func (this SealedSegment) Hash() SegmentHash {
	return this.hash
}

func (this SealedSegment) Size() int64 {
	return this.size
}

func (this SealedSegment) Content() io.ReadSeeker {
	if isNilRemoteValue(this.content) || this.size <= 0 {
		return nil
	}
	return io.NewSectionReader(this.content, 0, this.size)
}

func (this SealedSegment) FileName() string {
	return nativeSegmentName(this.sequence, journalHash(this.hash), this.encrypted)
}

func (this SealedSegment) RemotePath() string {
	return path.Join(this.producerId.String(), this.FileName())
}

// RemoteTarget publishes complete sealed segments under SealedSegment's
// RemotePath. Publish must honor context cancellation and be idempotent:
// identical existing content succeeds, conflicting content is rejected, and
// partial content is never exposed under the final path. Close must be
// idempotent and safe after the coordinator cancels an active Publish context.
// A custom Close must not wait for Publish unless it also unblocks that call.
// Retry and retention policies are owned by the coordinator.
type RemoteTarget interface {
	Publish(context.Context, SealedSegment) error
	io.Closer
}

func remoteDeliveryTargetSettings(conf configuration.AuditlogTargetV) (time.Duration, remoteDeliveryDestinationFingerprint, error) {
	switch value := conf.(type) {
	case *configuration.AuditlogTargetS3:
		values, err := value.Render(nil)
		if err != nil {
			return 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("cannot render S3 remote delivery settings: %w", err)
		}
		endpoint, err := normalizedS3RemoteEndpoint(value.Endpoint)
		if err != nil {
			return 0, remoteDeliveryDestinationFingerprint{}, err
		}
		return s3RemoteDeliveryTargetSettings(value, values, endpoint)
	case *configuration.AuditlogTargetWebdav:
		values, err := value.Render(nil)
		if err != nil {
			return 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("cannot render WebDAV remote delivery settings: %w", err)
		}
		endpoint, err := normalizedWebdavRemoteEndpoint(value.Endpoint)
		if err != nil {
			return 0, remoteDeliveryDestinationFingerprint{}, err
		}
		return webdavRemoteDeliveryTargetSettings(values, endpoint)
	case *configuration.AuditlogTargetSftp:
		values, err := value.Render(nil)
		if err != nil {
			return 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("cannot render SFTP remote delivery settings: %w", err)
		}
		address, err := normalizedSftpRemoteAddress(value.Address)
		if err != nil {
			return 0, remoteDeliveryDestinationFingerprint{}, err
		}
		return sftpRemoteDeliveryTargetSettings(value, values, address)
	default:
		return 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("custom remote target configuration %T requires an explicit destination identity from its factory", conf)
	}
}

func customRemoteDeliveryTargetSettings(conf configuration.AuditlogTargetV, settings RemoteTargetSettings) (time.Duration, remoteDeliveryDestinationFingerprint, error) {
	if settings.DestinationIdentity == "" {
		return 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("custom remote target configuration %T returned an empty destination identity", conf)
	}
	if settings.PublishAttemptTimeout <= 0 {
		return 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("custom remote target configuration %T returned a non-positive publish-attempt timeout", conf)
	}
	targetType := reflect.TypeOf(conf).String()
	if len(conf.Types()) > 0 {
		targetType = strings.ToLower(conf.Types()[0])
	}
	destination := struct {
		Type     string                          `json:"type"`
		Identity RemoteTargetDestinationIdentity `json:"identity"`
	}{targetType, settings.DestinationIdentity}
	return newRemoteDeliveryTargetSettings(settings.PublishAttemptTimeout, destination)
}

func s3RemoteDeliveryTargetSettings(conf *configuration.AuditlogTargetS3, values configuration.AuditlogTargetS3Values, endpoint string) (time.Duration, remoteDeliveryDestinationFingerprint, error) {
	destination := struct {
		Type                string `json:"type"`
		Endpoint            string `json:"endpoint"`
		Region              string `json:"region"`
		Bucket              string `json:"bucket"`
		Prefix              string `json:"prefix"`
		PathStyle           bool   `json:"pathStyle"`
		ExpectedBucketOwner string `json:"expectedBucketOwner"`
		DestinationIdentity string `json:"destinationIdentity"`
	}{"s3", endpoint, values.Region, conf.Bucket, conf.Prefix, conf.PathStyle, conf.ExpectedBucketOwner, conf.DestinationIdentity}
	return newRemoteDeliveryTargetSettings(values.PublishAttemptTimeout, destination)
}

func webdavRemoteDeliveryTargetSettings(values configuration.AuditlogTargetWebdavValues, endpoint *url.URL) (time.Duration, remoteDeliveryDestinationFingerprint, error) {
	destination := struct {
		Type     string `json:"type"`
		Endpoint string `json:"endpoint"`
		Username string `json:"username"`
	}{"webdav", endpoint.String(), values.Username}
	return newRemoteDeliveryTargetSettings(values.PublishAttemptTimeout, destination)
}

func sftpRemoteDeliveryTargetSettings(conf *configuration.AuditlogTargetSftp, values configuration.AuditlogTargetSftpValues, address string) (time.Duration, remoteDeliveryDestinationFingerprint, error) {
	destination := struct {
		Type      string `json:"type"`
		Address   string `json:"address"`
		Directory string `json:"directory"`
		Username  string `json:"username"`
	}{"sftp", address, conf.Directory, values.User}
	return newRemoteDeliveryTargetSettings(values.PublishAttemptTimeout, destination)
}

func normalizedS3RemoteEndpoint(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", errors.Config.Newf("cannot parse effective S3 remote destination: %w", err)
	}
	return normalizeRemoteHTTPURL(parsed).String(), nil
}

func normalizedWebdavRemoteEndpoint(value string) (*url.URL, error) {
	endpoint, err := url.Parse(value)
	if err != nil {
		return nil, errors.Config.Newf("cannot parse effective WebDAV remote destination: %w", err)
	}
	endpoint = normalizeRemoteHTTPURL(endpoint)
	if !strings.HasSuffix(endpoint.Path, "/") {
		endpoint.Path += "/"
		endpoint.RawPath = ""
	}
	return endpoint, nil
}

func normalizedSftpRemoteAddress(value string) (string, error) {
	address, err := bfssh.ParseAddress(value)
	if err != nil {
		return "", errors.Config.Newf("cannot parse effective SFTP remote destination: %w", err)
	}
	if len(address.Host.IP) == 0 {
		if ip, ipErr := netip.ParseAddr(address.Host.Dns); ipErr == nil {
			address.Host.Dns = ip.String()
		} else {
			address.Host.Dns = strings.ToLower(address.Host.Dns)
		}
	}
	return address.String(), nil
}

func newRemoteDeliveryTargetSettings(timeout time.Duration, destination any) (time.Duration, remoteDeliveryDestinationFingerprint, error) {
	if timeout <= 0 {
		return 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("remote publish-attempt timeout must be positive")
	}
	payload, err := json.Marshal(destination)
	if err != nil {
		return 0, remoteDeliveryDestinationFingerprint{}, errors.System.Newf("cannot encode remote destination identity: %w", err)
	}
	fingerprint := sha256.Sum256(append([]byte(remoteDeliveryDestinationFingerprintDomain), payload...))
	return timeout, remoteDeliveryDestinationFingerprint(fingerprint), nil
}

func normalizeRemoteHTTPURL(value *url.URL) *url.URL {
	result := *value
	result.Scheme = strings.ToLower(result.Scheme)
	hostname := strings.ToLower(result.Hostname())
	port := result.Port()
	if parsedPort, err := strconv.ParseUint(port, 10, 16); err == nil {
		port = strconv.FormatUint(parsedPort, 10)
	}
	if result.Scheme == "http" && port == "80" || result.Scheme == "https" && port == "443" {
		port = ""
	}
	if port != "" {
		result.Host = net.JoinHostPort(hostname, port)
	} else if strings.ContainsRune(hostname, ':') {
		result.Host = "[" + hostname + "]"
	} else {
		result.Host = hostname
	}
	return &result
}

func isNilRemoteValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func newRemoteTargetCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(parent), remoteTargetCleanupTimeout)
}
