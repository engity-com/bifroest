package audit

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	goerrors "errors"
	"hash"
	"io"
	"net"
	"net/http"
	"path"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

var _ = registerPreparedRemoteTarget(
	func() configuration.AuditlogTargetV { return &configuration.AuditlogTargetS3{} },
	prepareS3RemoteTarget,
)

type s3RemoteAPI interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

type s3RemoteTarget struct {
	mutex               sync.RWMutex
	client              s3RemoteAPI
	bucket              string
	prefix              string
	expectedBucketOwner string
	close               func()
	closed              bool
	closeErr            error
}

func newS3RemoteTarget(ctx context.Context, _ RemoteTargetScope, conf *configuration.AuditlogTargetS3) (RemoteTarget, error) {
	target, _, _, err := prepareS3RemoteTarget(ctx, RemoteTargetScope{}, conf)
	return target, err
}

func prepareS3RemoteTarget(ctx context.Context, _ RemoteTargetScope, conf *configuration.AuditlogTargetS3) (RemoteTarget, time.Duration, remoteDeliveryDestinationFingerprint, error) {
	if conf == nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("nil S3 audit target configuration")
	}
	snapshot := *conf
	conf = &snapshot
	if err := conf.Validate(); err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("invalid S3 audit target configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, err
	}
	values, err := conf.Render(nil)
	if err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("cannot render S3 audit target configuration: %w", err)
	}
	endpoint, err := normalizedS3RemoteEndpoint(conf.Endpoint)
	if err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, err
	}
	timeout, fingerprint, err := s3RemoteDeliveryTargetSettings(conf, values, endpoint)
	if err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	bfcrypto.AdjustHttpTransportWithCaCerts(transport)
	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	sdkConfig := aws.Config{
		Region: values.Region,
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
			values.AccessKeyId, values.SecretAccessKey, values.SessionToken,
		)),
		HTTPClient: httpClient,
		Retryer:    func() aws.Retryer { return aws.NopRetryer{} },
	}
	client := s3.NewFromConfig(sdkConfig, func(options *s3.Options) {
		options.BaseEndpoint = nil
		if endpoint != "" {
			options.BaseEndpoint = aws.String(endpoint)
		}
		options.UsePathStyle = conf.PathStyle
	})
	target, err := newS3RemoteTargetWithClient(conf, client, transport.CloseIdleConnections)
	if err != nil {
		transport.CloseIdleConnections()
	}
	return target, timeout, fingerprint, err
}

func newS3RemoteTargetWithClient(conf *configuration.AuditlogTargetS3, client s3RemoteAPI, close func()) (*s3RemoteTarget, error) {
	if conf == nil {
		return nil, errors.Config.Newf("nil S3 audit target configuration")
	}
	if err := conf.Validate(); err != nil {
		return nil, errors.Config.Newf("invalid S3 audit target configuration: %w", err)
	}
	if isNilRemoteValue(client) {
		return nil, errors.System.Newf("nil S3 client")
	}
	return &s3RemoteTarget{
		client: client, bucket: conf.Bucket, prefix: conf.Prefix,
		expectedBucketOwner: conf.ExpectedBucketOwner, close: close,
	}, nil
}

func (this *s3RemoteTarget) Publish(ctx context.Context, segment SealedSegment) error {
	this.mutex.RLock()
	defer this.mutex.RUnlock()
	if this.closed {
		return errors.System.Newf("S3 audit target is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	checksum, err := hashS3Segment(ctx, segment.Content())
	if err != nil {
		return err
	}
	key := segment.RemotePath()
	if this.prefix != "" {
		key = path.Join(this.prefix, key)
	}
	input := &s3.PutObjectInput{
		Bucket:         aws.String(this.bucket),
		Key:            aws.String(key),
		Body:           segment.Content(),
		ContentLength:  aws.Int64(segment.Size()),
		ContentType:    aws.String("application/octet-stream"),
		IfNoneMatch:    aws.String("*"),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(checksum)),
	}
	if this.expectedBucketOwner != "" {
		input.ExpectedBucketOwner = aws.String(this.expectedBucketOwner)
	}
	_, err = this.client.PutObject(ctx, input)
	if err == nil {
		return nil
	}
	status := s3RemoteStatusCode(err)
	if status != http.StatusConflict && status != http.StatusPreconditionFailed {
		return classifyS3RemoteError(ctx, "publish audit segment to S3", err)
	}
	return this.verifyExisting(ctx, key, segment, checksum)
}

func hashS3Segment(ctx context.Context, content io.Reader) ([]byte, error) {
	if content == nil {
		return nil, errors.System.Newf("nil sealed audit segment content")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, contextReader{context: ctx, reader: content}); err != nil {
		return nil, errors.System.Newf("cannot hash sealed audit segment for S3: %w", err)
	}
	return hasher.Sum(nil), nil
}

func (this *s3RemoteTarget) verifyExisting(ctx context.Context, key string, segment SealedSegment, expectedChecksum []byte) error {
	input := &s3.GetObjectInput{Bucket: aws.String(this.bucket), Key: aws.String(key)}
	if this.expectedBucketOwner != "" {
		input.ExpectedBucketOwner = aws.String(this.expectedBucketOwner)
	}
	output, err := this.client.GetObject(ctx, input)
	if err != nil {
		if s3RemoteStatusCode(err) == http.StatusNotFound && s3RemoteAPIErrorCode(err) != "NoSuchBucket" {
			return errors.Network.Newf("cannot read existing S3 audit segment: %w", err)
		}
		return classifyS3RemoteError(ctx, "read existing S3 audit segment", err)
	}
	if output == nil || output.Body == nil {
		return errors.Network.Newf("S3 returned no content for existing audit segment %q", key)
	}
	conflict := func(message string, args ...any) error {
		return errors.System.Newf("existing S3 audit segment %q conflicts with local content: "+message, append([]any{key}, args...)...)
	}
	if output.ContentLength != nil && *output.ContentLength != segment.Size() {
		return goerrors.Join(conflict("size is %d instead of %d", *output.ContentLength, segment.Size()), closeS3Object(output.Body, key))
	}
	hasher := sha256.New()
	read, readErr := copyS3Object(ctx, hasher, output.Body, segment.Size()+1)
	closeErr := closeS3Object(output.Body, key)
	if readErr != nil {
		return goerrors.Join(readErr, closeErr)
	}
	if read != segment.Size() {
		return goerrors.Join(conflict("size is %d instead of %d", read, segment.Size()), closeErr)
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), expectedChecksum) != 1 {
		return goerrors.Join(conflict("SHA-256 checksum differs"), closeErr)
	}
	return closeErr
}

func copyS3Object(ctx context.Context, target hash.Hash, source io.Reader, limit int64) (int64, error) {
	read, err := io.Copy(target, contextReader{context: ctx, reader: io.LimitReader(source, limit)})
	if err != nil {
		return read, errors.Network.Newf("cannot read existing S3 audit segment: %w", err)
	}
	return read, nil
}

func closeS3Object(body io.ReadCloser, key string) error {
	if err := body.Close(); err != nil {
		return errors.Network.Newf("cannot close existing S3 audit segment %q: %w", key, err)
	}
	return nil
}

type contextReader struct {
	context context.Context
	reader  io.Reader
}

func (this contextReader) Read(target []byte) (int, error) {
	if err := this.context.Err(); err != nil {
		return 0, err
	}
	return this.reader.Read(target)
}

func s3RemoteStatusCode(err error) int {
	var statusError interface{ HTTPStatusCode() int }
	if goerrors.As(err, &statusError) {
		return statusError.HTTPStatusCode()
	}
	return 0
}

func s3RemoteAPIErrorCode(err error) string {
	var apiError smithy.APIError
	if goerrors.As(err, &apiError) {
		return apiError.ErrorCode()
	}
	return ""
}

func classifyS3RemoteError(ctx context.Context, operation string, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if goerrors.Is(err, context.Canceled) || goerrors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var serializationError *smithy.SerializationError
	if goerrors.As(err, &serializationError) {
		return errors.System.Newf("cannot %s: %w", operation, err)
	}
	switch s3RemoteAPIErrorCode(err) {
	case "AccessDenied", "AccessDeniedException", "ExpiredToken", "ExpiredTokenException", "InvalidAccessKeyId",
		"InvalidToken", "InvalidTokenException", "SignatureDoesNotMatch", "TokenRefreshRequired", "UnrecognizedClientException":
		return errors.Permission.Newf("cannot %s: %w", operation, err)
	case "AuthorizationHeaderMalformed", "IllegalLocationConstraintException", "IncorrectEndpoint", "InvalidBucketName",
		"NoSuchBucket", "PermanentRedirect":
		return errors.Config.Newf("cannot %s: %w", operation, err)
	case "RequestTimeout", "RequestTimeoutException", "SlowDown":
		return errors.Network.Newf("cannot %s: %w", operation, err)
	}
	var apiError smithy.APIError
	if goerrors.As(err, &apiError) && apiError.ErrorFault() == smithy.FaultServer {
		return errors.Network.Newf("cannot %s: %w", operation, err)
	}
	status := s3RemoteStatusCode(err)
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return errors.Permission.Newf("cannot %s: %w", operation, err)
	case status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500:
		return errors.Network.Newf("cannot %s: %w", operation, err)
	case status >= 300 && status < 500:
		return errors.Config.Newf("cannot %s: %w", operation, err)
	}
	var networkError net.Error
	if goerrors.As(err, &networkError) {
		return errors.Network.Newf("cannot %s: %w", operation, err)
	}
	var signingError *awsv4.SigningError
	if goerrors.As(err, &signingError) {
		return errors.Permission.Newf("cannot %s: %w", operation, err)
	}
	return errors.System.Newf("cannot %s: %w", operation, err)
}

func (this *s3RemoteTarget) Close() error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return this.closeErr
	}
	this.closed = true
	if this.close != nil {
		this.close()
	}
	return this.closeErr
}
