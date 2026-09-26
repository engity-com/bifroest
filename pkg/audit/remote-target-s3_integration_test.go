package audit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
)

type embeddedS3RequestState struct {
	objectPuts           atomic.Int32
	objectGets           atomic.Int32
	conditionalPuts      atomic.Int32
	checksumPuts         atomic.Int32
	preconditionFailures atomic.Int32
	unsignedRequests     atomic.Int32
	missingTokens        atomic.Int32
}

type embeddedS3ResponseWriter struct {
	http.ResponseWriter
	status int
}

func (this *embeddedS3ResponseWriter) WriteHeader(status int) {
	this.status = status
	this.ResponseWriter.WriteHeader(status)
}

func (this *embeddedS3ResponseWriter) Write(content []byte) (int, error) {
	if this.status == 0 {
		this.status = http.StatusOK
	}
	return this.ResponseWriter.Write(content)
}

func TestS3RemoteTargetPublishesAgainstEmbeddedS3Server(t *testing.T) {
	target, client, state := newEmbeddedS3RemoteTestTarget(t, "production")
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	key := "production/" + segment.RemotePath()

	require.NoError(t, target.Publish(context.Background(), segment))
	require.Equal(t, int32(1), state.objectPuts.Load())
	require.Zero(t, state.objectGets.Load())
	require.Equal(t, int32(1), state.conditionalPuts.Load())
	require.Equal(t, int32(1), state.checksumPuts.Load())

	require.NoError(t, target.Publish(context.Background(), segment))
	require.Equal(t, int32(2), state.objectPuts.Load())
	require.Equal(t, int32(1), state.objectGets.Load())
	require.Equal(t, int32(2), state.conditionalPuts.Load())
	require.Equal(t, int32(2), state.checksumPuts.Load())
	require.Equal(t, int32(1), state.preconditionFailures.Load())
	require.Equal(t, content, readEmbeddedS3Object(t, client, key))

	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("audit-archive"),
		Key:    aws.String(key),
		Body:   strings.NewReader("conflicting"),
	})
	require.NoError(t, err)
	err = target.Publish(context.Background(), segment)
	require.ErrorContains(t, err, "conflicts with local content")
	require.True(t, bferrors.System.IsErr(err), err)
	require.Equal(t, int32(4), state.objectPuts.Load())
	require.Equal(t, int32(3), state.conditionalPuts.Load())
	require.Equal(t, int32(3), state.checksumPuts.Load())
	require.Equal(t, int32(2), state.preconditionFailures.Load())
	require.Equal(t, []byte("conflicting"), readEmbeddedS3Object(t, client, key))
	require.Zero(t, state.unsignedRequests.Load())
	require.Zero(t, state.missingTokens.Load())
}

func TestS3RemoteTargetPublishesNativeAuditVector(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "clear"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			target, client, _ := newEmbeddedS3RemoteTestTarget(t, "production")
			segment, vector, fingerprint := nativeRemoteTestSegment(t, encrypted)
			require.NoError(t, target.Publish(context.Background(), segment))
			key := "production/" + segment.RemotePath()
			verifyRetrievedNativeRemoteTestSegment(t, segment, vector, fingerprint, readEmbeddedS3Object(t, client, key))
		})
	}
}

func TestS3RemoteTargetConcurrentPublicationAgainstEmbeddedServer(t *testing.T) {
	target, client, state := newEmbeddedS3RemoteTestTarget(t, "")
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)

	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- target.Publish(context.Background(), segment)
		}()
	}
	close(start)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	require.Equal(t, int32(2), state.objectPuts.Load())
	require.Equal(t, int32(1), state.objectGets.Load())
	require.Equal(t, int32(2), state.conditionalPuts.Load())
	require.Equal(t, int32(2), state.checksumPuts.Load())
	require.Equal(t, int32(1), state.preconditionFailures.Load())
	require.Equal(t, content, readEmbeddedS3Object(t, client, segment.RemotePath()))
}

func TestS3RemoteTargetClassifiesMissingBucketAgainstEmbeddedServer(t *testing.T) {
	target, client, state := newEmbeddedS3RemoteTestTarget(t, "")
	_, err := client.DeleteBucket(context.Background(), &s3.DeleteBucketInput{Bucket: aws.String("audit-archive")})
	require.NoError(t, err)

	err = target.Publish(context.Background(), validRemoteTargetTestSegment())
	require.True(t, bferrors.Config.IsErr(err), err)
	require.ErrorContains(t, err, "NoSuchBucket")
	require.Equal(t, int32(1), state.objectPuts.Load())
	require.Equal(t, int32(1), state.conditionalPuts.Load())
	require.Equal(t, int32(1), state.checksumPuts.Load())
	require.Zero(t, state.unsignedRequests.Load())
	require.Zero(t, state.missingTokens.Load())
}

func newEmbeddedS3RemoteTestTarget(t *testing.T, prefix string) (*s3RemoteTarget, *s3.Client, *embeddedS3RequestState) {
	t.Helper()
	backend := s3mem.New()
	serverHandler := gofakes3.New(backend).Server()
	state := &embeddedS3RequestState{}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		capturedResponse := &embeddedS3ResponseWriter{ResponseWriter: response}
		if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			state.unsignedRequests.Add(1)
		}
		if request.Header.Get("X-Amz-Security-Token") != "session-token" {
			state.missingTokens.Add(1)
		}
		if strings.HasPrefix(request.URL.Path, "/audit-archive/") {
			switch request.Method {
			case http.MethodPut:
				state.objectPuts.Add(1)
				if request.Header.Get("If-None-Match") == "*" {
					state.conditionalPuts.Add(1)
				}
				if request.Header.Get("X-Amz-Checksum-Sha256") != "" {
					state.checksumPuts.Add(1)
				}
			case http.MethodGet:
				state.objectGets.Add(1)
			}
		}
		serverHandler.ServeHTTP(capturedResponse, request)
		if capturedResponse.status == http.StatusPreconditionFailed {
			state.preconditionFailures.Add(1)
		}
	})
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	client := s3.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("access-key", "secret-key", "session-token")),
		HTTPClient:  server.Client(),
		Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
	}, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(server.URL)
		options.UsePathStyle = true
	})
	_, err := client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String("audit-archive")})
	require.NoError(t, err)

	conf := &configuration.AuditlogTargetS3{
		Bucket:              "audit-archive",
		Region:              template.MustNewString("us-east-1"),
		Prefix:              prefix,
		Endpoint:            server.URL,
		PathStyle:           true,
		DestinationIdentity: "embedded-test-tenant",
		AccessKeyId:         template.MustNewString("access-key"),
		SecretAccessKey:     template.MustNewString("secret-key"),
		SessionToken:        template.MustNewString("session-token"),
	}
	target, err := newS3RemoteTargetWithClient(conf, client, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, target.Close()) })
	return target, client, state
}

func readEmbeddedS3Object(t *testing.T, client *s3.Client, key string) []byte {
	t.Helper()
	output, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String("audit-archive"),
		Key:    aws.String(key),
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, output.Body.Close()) }()
	content, err := io.ReadAll(output.Body)
	require.NoError(t, err)
	return content
}
