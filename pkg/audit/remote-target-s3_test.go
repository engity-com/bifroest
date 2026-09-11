package audit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	goerrors "errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
)

type s3RemoteTestClient struct {
	put func(context.Context, *s3.PutObjectInput) (*s3.PutObjectOutput, error)
	get func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error)
}

func (this *s3RemoteTestClient) PutObject(ctx context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if this.put == nil {
		return nil, goerrors.New("unexpected PutObject")
	}
	return this.put(ctx, input)
}

func (this *s3RemoteTestClient) GetObject(ctx context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if this.get == nil {
		return nil, goerrors.New("unexpected GetObject")
	}
	return this.get(ctx, input)
}

type s3RemoteStatusError int

func (this s3RemoteStatusError) Error() string       { return http.StatusText(int(this)) }
func (this s3RemoteStatusError) HTTPStatusCode() int { return int(this) }

type s3RemoteNetworkError struct{}

func (s3RemoteNetworkError) Error() string   { return "network failure" }
func (s3RemoteNetworkError) Timeout() bool   { return false }
func (s3RemoteNetworkError) Temporary() bool { return true }

type s3RemoteTestBody struct {
	io.Reader
	closed   atomic.Int32
	closeErr error
}

func (this *s3RemoteTestBody) Close() error {
	this.closed.Add(1)
	return this.closeErr
}

func TestS3RemoteTargetPublishesConditionalSingleObject(t *testing.T) {
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	checksum := sha256.Sum256(content)
	client := &s3RemoteTestClient{put: func(ctx context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
		require.NoError(t, ctx.Err())
		require.Equal(t, "audit-archive", aws.ToString(input.Bucket))
		require.Equal(t, "production/"+segment.RemotePath(), aws.ToString(input.Key))
		require.Equal(t, "*", aws.ToString(input.IfNoneMatch))
		require.Equal(t, "123456789012", aws.ToString(input.ExpectedBucketOwner))
		require.Equal(t, segment.Size(), aws.ToInt64(input.ContentLength))
		require.Equal(t, "application/octet-stream", aws.ToString(input.ContentType))
		require.Equal(t, base64.StdEncoding.EncodeToString(checksum[:]), aws.ToString(input.ChecksumSHA256))
		actual, readErr := io.ReadAll(input.Body)
		require.NoError(t, readErr)
		require.Equal(t, content, actual)
		return &s3.PutObjectOutput{}, nil
	}}
	target := newS3RemoteTestTarget(t, client, "production")
	require.NoError(t, target.Publish(context.Background(), segment))
}

func TestS3RemoteTargetAcceptsIdenticalExistingObject(t *testing.T) {
	for _, status := range []int{http.StatusConflict, http.StatusPreconditionFailed} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			segment := validRemoteTargetTestSegment()
			content, err := io.ReadAll(segment.Content())
			require.NoError(t, err)
			body := &s3RemoteTestBody{Reader: strings.NewReader(string(content))}
			client := &s3RemoteTestClient{
				put: func(context.Context, *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
					return nil, s3RemoteStatusError(status)
				},
				get: func(_ context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
					require.Equal(t, segment.RemotePath(), aws.ToString(input.Key))
					require.Equal(t, "123456789012", aws.ToString(input.ExpectedBucketOwner))
					return &s3.GetObjectOutput{Body: body, ContentLength: aws.Int64(int64(len(content)))}, nil
				},
			}
			target := newS3RemoteTestTarget(t, client, "")
			require.NoError(t, target.Publish(context.Background(), segment))
			require.Equal(t, int32(1), body.closed.Load())
		})
	}
}

func TestS3RemoteTargetRejectsConflictingExistingObject(t *testing.T) {
	segment := validRemoteTargetTestSegment()
	client := &s3RemoteTestClient{
		put: func(context.Context, *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
			return nil, s3RemoteStatusError(http.StatusPreconditionFailed)
		},
		get: func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return &s3.GetObjectOutput{Body: &s3RemoteTestBody{Reader: strings.NewReader("different data")}}, nil
		},
	}
	target := newS3RemoteTestTarget(t, client, "")
	err := target.Publish(context.Background(), segment)
	require.ErrorContains(t, err, "conflicts with local content")
	require.True(t, bferrors.System.IsErr(err))
}

func TestS3RemoteTargetClassifiesRemoteFailures(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		errorType bferrors.Type
		getStatus int
	}{
		{"permission", http.StatusForbidden, bferrors.Permission, 0},
		{"network", http.StatusServiceUnavailable, bferrors.Network, 0},
		{"configuration", http.StatusNotFound, bferrors.Config, 0},
		{"local", 0, bferrors.System, 0},
		{"conflict-read", http.StatusPreconditionFailed, bferrors.Network, http.StatusServiceUnavailable},
		{"conflict-missing", http.StatusPreconditionFailed, bferrors.Network, http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &s3RemoteTestClient{put: func(context.Context, *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
				return nil, s3RemoteStatusError(test.status)
			}}
			if test.getStatus != 0 {
				client.get = func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
					return nil, s3RemoteStatusError(test.getStatus)
				}
			}
			target := newS3RemoteTestTarget(t, client, "")
			err := target.Publish(context.Background(), validRemoteTargetTestSegment())
			require.Error(t, err)
			require.True(t, test.errorType.IsErr(err), err)
		})
	}
}

func TestS3RemoteTargetClassifiesAPIFailures(t *testing.T) {
	tests := []struct {
		code      string
		errorType bferrors.Type
	}{
		{"ExpiredToken", bferrors.Permission},
		{"NoSuchBucket", bferrors.Config},
		{"RequestTimeout", bferrors.Network},
		{"InternalError", bferrors.Network},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			fault := smithy.FaultClient
			if test.code == "InternalError" {
				fault = smithy.FaultServer
			}
			err := classifyS3RemoteError(context.Background(), "test S3", &smithy.GenericAPIError{
				Code: test.code, Message: "failure", Fault: fault,
			})
			require.True(t, test.errorType.IsErr(err), err)
		})
	}
}

func TestS3RemoteTargetClassifiesCredentialProviderFailures(t *testing.T) {
	require.True(t, bferrors.Network.IsErr(classifyS3RemoteError(context.Background(), "sign S3 request", &awsv4.SigningError{
		Err: s3RemoteNetworkError{},
	})))
	require.True(t, bferrors.Permission.IsErr(classifyS3RemoteError(context.Background(), "sign S3 request", &awsv4.SigningError{
		Err: goerrors.New("credentials unavailable"),
	})))
}

func TestS3RemoteTargetContextAndClose(t *testing.T) {
	var puts atomic.Int32
	var closes atomic.Int32
	client := &s3RemoteTestClient{put: func(context.Context, *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
		puts.Add(1)
		return &s3.PutObjectOutput{}, nil
	}}
	conf := validS3RemoteTestConfiguration("")
	target, err := newS3RemoteTargetWithClient(conf, client, func() { closes.Add(1) })
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	err = target.Publish(canceled, validRemoteTargetTestSegment())
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, puts.Load())
	require.NoError(t, target.Close())
	require.NoError(t, target.Close())
	require.Equal(t, int32(1), closes.Load())
	require.ErrorContains(t, target.Publish(context.Background(), validRemoteTargetTestSegment()), "closed")
}

func TestS3RemoteTargetCloseWaitsForPublish(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	client := &s3RemoteTestClient{put: func(context.Context, *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
		close(started)
		<-release
		return &s3.PutObjectOutput{}, nil
	}}
	target := newS3RemoteTestTarget(t, client, "")
	published := make(chan error, 1)
	go func() { published <- target.Publish(context.Background(), validRemoteTargetTestSegment()) }()
	<-started
	closed := make(chan error, 1)
	go func() { closed <- target.Close() }()
	select {
	case <-closed:
		t.Fatal("Close returned while Publish was active")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-published)
	require.NoError(t, <-closed)
}

func TestS3RemoteTargetSDKRequestAndNoRetry(t *testing.T) {
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	t.Run("request", func(t *testing.T) {
		var request *http.Request
		client := newS3RemoteSDKTestClient(roundTripFunc(func(actual *http.Request) (*http.Response, error) {
			request = actual
			body, readErr := io.ReadAll(actual.Body)
			require.NoError(t, readErr)
			require.Equal(t, content, body)
			return s3RemoteHTTPResponse(actual, http.StatusOK, ""), nil
		}))
		target := newS3RemoteTestTarget(t, client, "production")
		require.NoError(t, target.Publish(context.Background(), segment))
		require.Equal(t, http.MethodPut, request.Method)
		require.Equal(t, "/audit-archive/production/"+segment.RemotePath(), request.URL.Path)
		require.Equal(t, "*", request.Header.Get("If-None-Match"))
		require.Equal(t, "123456789012", request.Header.Get("X-Amz-Expected-Bucket-Owner"))
		require.NotEmpty(t, request.Header.Get("X-Amz-Checksum-Sha256"))
		require.Contains(t, request.Header.Get("Authorization"), "AWS4-HMAC-SHA256")
		require.Equal(t, segment.Size(), request.ContentLength)
		require.NotContains(t, request.URL.RawQuery, "uploads")
	})
	t.Run("single-attempt", func(t *testing.T) {
		var attempts atomic.Int32
		client := newS3RemoteSDKTestClient(roundTripFunc(func(request *http.Request) (*http.Response, error) {
			attempts.Add(1)
			return s3RemoteHTTPResponse(request, http.StatusServiceUnavailable, `<Error><Code>ServiceUnavailable</Code></Error>`), nil
		}))
		target := newS3RemoteTestTarget(t, client, "")
		err := target.Publish(context.Background(), segment)
		require.Error(t, err)
		require.True(t, bferrors.Network.IsErr(err))
		require.Equal(t, int32(1), attempts.Load())
	})
}

func TestNewS3RemoteTargetUsesPerTargetCredentialsAndPinsEndpoint(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "environment-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "environment-secret")
	t.Setenv("AWS_SESSION_TOKEN", "environment-token")
	t.Setenv("AWS_ENDPOINT_URL", "https://environment.example.invalid")
	t.Setenv("AWS_ENDPOINT_URL_S3", "https://s3-environment.example.invalid")

	conf := &configuration.AuditlogTargetS3{}
	require.NoError(t, conf.SetDefaults())
	conf.Bucket = "audit-archive"
	conf.Region = template.MustNewString("eu-central-1")
	conf.ExpectedBucketOwner = "123456789012"
	conf.AccessKeyId = template.MustNewString("first-access")
	conf.SecretAccessKey = template.MustNewString("first-secret")
	raw, err := newS3RemoteTarget(context.Background(), RemoteTargetScope{Auditlog: "security", Target: "archive"}, conf)
	require.NoError(t, err)
	first := raw.(*s3RemoteTarget)
	firstOptions := first.client.(*s3.Client).Options()
	require.Nil(t, firstOptions.BaseEndpoint)
	require.Equal(t, "eu-central-1", firstOptions.Region)
	require.Equal(t, 1, firstOptions.Retryer.MaxAttempts())
	firstCredentials, err := firstOptions.Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	require.Equal(t, "first-access", firstCredentials.AccessKeyID)
	require.Equal(t, "first-secret", firstCredentials.SecretAccessKey)
	require.Empty(t, firstCredentials.SessionToken)

	conf.Endpoint = "https://configured.example.invalid"
	conf.AccessKeyId = template.MustNewString("second-access")
	conf.SecretAccessKey = template.MustNewString("second-secret")
	conf.SessionToken = template.MustNewString("second-token")
	raw, err = newS3RemoteTarget(context.Background(), RemoteTargetScope{Auditlog: "security", Target: "archive"}, conf)
	require.NoError(t, err)
	second := raw.(*s3RemoteTarget)
	secondOptions := second.client.(*s3.Client).Options()
	require.Equal(t, conf.Endpoint, aws.ToString(secondOptions.BaseEndpoint))
	require.Equal(t, 1, secondOptions.Retryer.MaxAttempts())
	secondCredentials, err := secondOptions.Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	require.Equal(t, "second-access", secondCredentials.AccessKeyID)
	require.Equal(t, "second-secret", secondCredentials.SecretAccessKey)
	require.Equal(t, "second-token", secondCredentials.SessionToken)

	firstCredentials, err = firstOptions.Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	require.Equal(t, "first-access", firstCredentials.AccessKeyID)
	require.Equal(t, "first-secret", firstCredentials.SecretAccessKey)
	require.NoError(t, second.Close())
	require.NoError(t, first.Close())
}

func TestNewS3RemoteTargetRejectsMissingRenderedCredentials(t *testing.T) {
	t.Setenv("MISSING_S3_ACCESS_KEY", "")
	conf := validS3RemoteTestConfiguration("")
	conf.AccessKeyId = template.MustNewString("{{ env `MISSING_S3_ACCESS_KEY` }}")

	target, err := newS3RemoteTarget(context.Background(), RemoteTargetScope{Auditlog: "security", Target: "archive"}, conf)
	require.Nil(t, target)
	require.ErrorContains(t, err, "[accessKeyId] required but absent after rendering")
	require.True(t, bferrors.Config.IsErr(err))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (this roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return this(request)
}

func newS3RemoteSDKTestClient(transport http.RoundTripper) *s3.Client {
	return s3.NewFromConfig(aws.Config{
		Region:      "eu-central-1",
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("access", "secret", "")),
		HTTPClient:  &http.Client{Transport: transport},
		Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
	}, func(options *s3.Options) {
		options.BaseEndpoint = aws.String("https://objects.example.invalid")
		options.UsePathStyle = true
	})
}

func s3RemoteHTTPResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/xml"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func newS3RemoteTestTarget(t *testing.T, client s3RemoteAPI, prefix string) *s3RemoteTarget {
	t.Helper()
	target, err := newS3RemoteTargetWithClient(validS3RemoteTestConfiguration(prefix), client, nil)
	require.NoError(t, err)
	return target
}

func validS3RemoteTestConfiguration(prefix string) *configuration.AuditlogTargetS3 {
	return &configuration.AuditlogTargetS3{
		Bucket: "audit-archive", Region: template.MustNewString("eu-central-1"), Prefix: prefix,
		ExpectedBucketOwner: "123456789012", AccessKeyId: template.MustNewString("access"),
		SecretAccessKey: template.MustNewString("secret"), SessionToken: template.MustNewString(""),
	}
}
