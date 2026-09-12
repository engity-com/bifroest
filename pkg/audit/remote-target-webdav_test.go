package audit

import (
	"bytes"
	"context"
	goerrors "errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"

	"github.com/engity-com/bifroest/pkg/configuration"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
)

type webdavRemoteTestClient struct {
	do func(*http.Request) (*http.Response, error)
}

func (this *webdavRemoteTestClient) Do(request *http.Request) (*http.Response, error) {
	if this.do == nil {
		return nil, goerrors.New("unexpected WebDAV request")
	}
	return this.do(request)
}

type webdavRemoteNetworkError struct{}

func (webdavRemoteNetworkError) Error() string   { return "network failure" }
func (webdavRemoteNetworkError) Timeout() bool   { return false }
func (webdavRemoteNetworkError) Temporary() bool { return true }

type webdavRemoteInterruptedReaderAt struct {
	content []byte
	passes  atomic.Int32
}

func (this *webdavRemoteInterruptedReaderAt) ReadAt(target []byte, offset int64) (int, error) {
	pass := this.passes.Load()
	if offset == 0 {
		pass = this.passes.Add(1)
	}
	if pass >= 2 {
		limit := int64(len(this.content) / 2)
		if offset >= limit {
			return 0, goerrors.New("interrupted upload")
		}
		if offset+int64(len(target)) > limit {
			target = target[:limit-offset]
		}
	}
	read, err := bytes.NewReader(this.content).ReadAt(target, offset)
	if pass >= 2 && offset+int64(read) >= int64(len(this.content)/2) {
		return read, goerrors.New("interrupted upload")
	}
	return read, err
}

func TestWebdavRemoteTargetPublishesThroughVerifiedTemporaryObject(t *testing.T) {
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	producerPath := "/audit/" + segment.ProducerId().String() + "/"
	finalURL := "https://dav.example.invalid" + producerPath + segment.FileName()
	var temporaryURL string
	step := 0
	client := &webdavRemoteTestClient{do: func(request *http.Request) (*http.Response, error) {
		username, password, basic := request.BasicAuth()
		require.True(t, basic)
		require.Equal(t, "archive-user", username)
		require.Equal(t, "archive-password", password)
		switch step {
		case 0:
			require.Equal(t, http.MethodGet, request.Method)
			require.Equal(t, finalURL, request.URL.String())
			require.Equal(t, "identity", request.Header.Get("Accept-Encoding"))
			require.Equal(t, "no-cache, no-store", request.Header.Get("Cache-Control"))
			step++
			return webdavRemoteResponse(http.StatusNotFound, ""), nil
		case 1:
			require.Equal(t, webdavMethodMkcol, request.Method)
			require.Equal(t, "https://dav.example.invalid"+producerPath, request.URL.String())
			step++
			return webdavRemoteResponse(http.StatusCreated, ""), nil
		case 2:
			require.Equal(t, http.MethodPut, request.Method)
			require.Contains(t, request.URL.Path, producerPath+".bifroest-upload-")
			require.True(t, strings.HasSuffix(request.URL.Path, ".tmp"))
			temporaryURL = request.URL.String()
			require.Equal(t, "*", request.Header.Get("If-None-Match"))
			require.Equal(t, "application/octet-stream", request.Header.Get("Content-Type"))
			require.Equal(t, segment.Size(), request.ContentLength)
			actual, readErr := io.ReadAll(request.Body)
			require.NoError(t, readErr)
			require.Equal(t, content, actual)
			step++
			return webdavRemoteResponse(http.StatusCreated, ""), nil
		case 3:
			require.Equal(t, http.MethodGet, request.Method)
			require.Equal(t, temporaryURL, request.URL.String())
			require.Equal(t, "no-cache, no-store", request.Header.Get("Cache-Control"))
			step++
			return webdavRemoteResponse(http.StatusOK, string(content)), nil
		case 4:
			require.Equal(t, webdavMethodMove, request.Method)
			require.Equal(t, temporaryURL, request.URL.String())
			require.Equal(t, finalURL, request.Header.Get("Destination"))
			require.Equal(t, "F", request.Header.Get("Overwrite"))
			step++
			return webdavRemoteResponse(http.StatusCreated, ""), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL)
			return nil, nil
		}
	}}
	target := newWebdavRemoteTestTarget(t, client, true)
	require.NoError(t, target.Publish(context.Background(), segment))
	require.Equal(t, 5, step)
}

func TestWebdavRemoteTargetAcceptsIdenticalExistingObject(t *testing.T) {
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	body := &s3RemoteTestBody{Reader: strings.NewReader(string(content))}
	var calls atomic.Int32
	client := &webdavRemoteTestClient{do: func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		require.Equal(t, http.MethodGet, request.Method)
		require.Empty(t, request.Header.Get("Authorization"))
		response := webdavRemoteResponse(http.StatusOK, "")
		response.Body = body
		response.ContentLength = int64(len(content))
		return response, nil
	}}
	target := newWebdavRemoteTestTarget(t, client, false)
	require.NoError(t, target.Publish(context.Background(), segment))
	require.Equal(t, int32(1), calls.Load())
	require.Equal(t, int32(1), body.closed.Load())
}

func TestWebdavRemoteTargetRejectsConflictingExistingObject(t *testing.T) {
	client := &webdavRemoteTestClient{do: func(*http.Request) (*http.Response, error) {
		return webdavRemoteResponse(http.StatusOK, "different"), nil
	}}
	target := newWebdavRemoteTestTarget(t, client, false)
	err := target.Publish(context.Background(), validRemoteTargetTestSegment())
	require.ErrorContains(t, err, "conflicts with local content")
	require.True(t, bferrors.System.IsErr(err))
}

func TestWebdavRemoteTargetResolvesMoveConflict(t *testing.T) {
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	step := 0
	client := &webdavRemoteTestClient{do: func(request *http.Request) (*http.Response, error) {
		step++
		switch step {
		case 1:
			return webdavRemoteResponse(http.StatusNotFound, ""), nil
		case 2:
			return webdavRemoteResponse(http.StatusMethodNotAllowed, ""), nil
		case 3:
			return webdavRemoteResponse(http.StatusCreated, ""), nil
		case 4:
			return webdavRemoteResponse(http.StatusOK, string(content)), nil
		case 5:
			return webdavRemoteResponse(http.StatusPreconditionFailed, ""), nil
		case 6:
			require.Equal(t, http.MethodDelete, request.Method)
			return webdavRemoteResponse(http.StatusAccepted, ""), nil
		case 7:
			require.Equal(t, http.MethodGet, request.Method)
			require.Equal(t, "no-cache, no-store", request.Header.Get("Cache-Control"))
			return webdavRemoteResponse(http.StatusOK, string(content)), nil
		default:
			t.Fatalf("unexpected request %d", step)
			return nil, nil
		}
	}}
	target := newWebdavRemoteTestTarget(t, client, false)
	require.NoError(t, target.Publish(context.Background(), segment))
	require.Equal(t, 7, step)
}

func TestWebdavRemoteTargetRejectsInvalidMoveConflictState(t *testing.T) {
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	tests := []struct {
		name      string
		status    int
		body      string
		errorType bferrors.Type
	}{
		{"missing", http.StatusNotFound, "", bferrors.Network},
		{"conflicting", http.StatusOK, "different", bferrors.System},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			step := 0
			client := &webdavRemoteTestClient{do: func(*http.Request) (*http.Response, error) {
				step++
				switch step {
				case 1:
					return webdavRemoteResponse(http.StatusNotFound, ""), nil
				case 2:
					return webdavRemoteResponse(http.StatusCreated, ""), nil
				case 3:
					return webdavRemoteResponse(http.StatusCreated, ""), nil
				case 4:
					return webdavRemoteResponse(http.StatusOK, string(content)), nil
				case 5:
					return webdavRemoteResponse(http.StatusPreconditionFailed, ""), nil
				case 6:
					return webdavRemoteResponse(http.StatusNoContent, ""), nil
				case 7:
					return webdavRemoteResponse(test.status, test.body), nil
				default:
					t.Fatalf("unexpected request %d", step)
					return nil, nil
				}
			}}
			target := newWebdavRemoteTestTarget(t, client, false)
			err := target.Publish(context.Background(), segment)
			require.True(t, test.errorType.IsErr(err), err)
			require.Equal(t, 7, step)
		})
	}
}

func TestWebdavRemoteTargetCleansUpInvalidTemporaryObject(t *testing.T) {
	step := 0
	client := &webdavRemoteTestClient{do: func(request *http.Request) (*http.Response, error) {
		step++
		switch step {
		case 1:
			return webdavRemoteResponse(http.StatusNotFound, ""), nil
		case 2, 3:
			return webdavRemoteResponse(http.StatusCreated, ""), nil
		case 4:
			return webdavRemoteResponse(http.StatusOK, "different"), nil
		case 5:
			require.Equal(t, http.MethodDelete, request.Method)
			return webdavRemoteResponse(http.StatusNoContent, ""), nil
		default:
			t.Fatalf("unexpected request %d", step)
			return nil, nil
		}
	}}
	target := newWebdavRemoteTestTarget(t, client, false)
	err := target.Publish(context.Background(), validRemoteTargetTestSegment())
	require.True(t, bferrors.System.IsErr(err), err)
	require.Equal(t, 5, step)
}

func TestWebdavRemoteTargetCleansUpFailedTemporaryUpload(t *testing.T) {
	step := 0
	client := &webdavRemoteTestClient{do: func(request *http.Request) (*http.Response, error) {
		step++
		switch step {
		case 1:
			return webdavRemoteResponse(http.StatusNotFound, ""), nil
		case 2:
			return webdavRemoteResponse(http.StatusCreated, ""), nil
		case 3:
			require.Equal(t, http.MethodPut, request.Method)
			return webdavRemoteResponse(http.StatusInternalServerError, ""), nil
		case 4:
			require.Equal(t, http.MethodDelete, request.Method)
			return webdavRemoteResponse(http.StatusNoContent, ""), nil
		default:
			t.Fatalf("unexpected request %d", step)
			return nil, nil
		}
	}}
	target := newWebdavRemoteTestTarget(t, client, false)
	err := target.Publish(context.Background(), validRemoteTargetTestSegment())
	require.True(t, bferrors.Network.IsErr(err), err)
	require.Equal(t, 4, step)
}

func TestWebdavRemoteTargetCleansUpCreatedUploadWithResponseError(t *testing.T) {
	step := 0
	client := &webdavRemoteTestClient{do: func(request *http.Request) (*http.Response, error) {
		step++
		switch step {
		case 1:
			return webdavRemoteResponse(http.StatusNotFound, ""), nil
		case 2:
			return webdavRemoteResponse(http.StatusCreated, ""), nil
		case 3:
			require.Equal(t, http.MethodPut, request.Method)
			response := webdavRemoteResponse(http.StatusCreated, "")
			response.Body = &s3RemoteTestBody{Reader: strings.NewReader(""), closeErr: goerrors.New("response close failed")}
			return response, nil
		case 4:
			require.Equal(t, http.MethodDelete, request.Method)
			return webdavRemoteResponse(http.StatusNoContent, ""), nil
		default:
			t.Fatalf("unexpected request %d", step)
			return nil, nil
		}
	}}
	target := newWebdavRemoteTestTarget(t, client, false)
	err := target.Publish(context.Background(), validRemoteTargetTestSegment())
	require.True(t, bferrors.Network.IsErr(err), err)
	require.ErrorContains(t, err, "response close failed")
	require.Equal(t, 4, step)
}

func TestWebdavRemoteTargetPreservesPreexistingTemporaryObject(t *testing.T) {
	step := 0
	client := &webdavRemoteTestClient{do: func(request *http.Request) (*http.Response, error) {
		step++
		switch step {
		case 1:
			return webdavRemoteResponse(http.StatusNotFound, ""), nil
		case 2:
			return webdavRemoteResponse(http.StatusCreated, ""), nil
		case 3:
			require.Equal(t, http.MethodPut, request.Method)
			return webdavRemoteResponse(http.StatusPreconditionFailed, ""), nil
		default:
			t.Fatalf("unexpected cleanup request after a precondition failure")
			return nil, nil
		}
	}}
	target := newWebdavRemoteTestTarget(t, client, false)
	err := target.Publish(context.Background(), validRemoteTargetTestSegment())
	require.True(t, bferrors.Network.IsErr(err), err)
	require.ErrorContains(t, err, "already exists")
	require.Equal(t, 3, step)
}

func TestWebdavRemoteTargetPublishesAgainstEmbeddedWebdavServer(t *testing.T) {
	target, fileSystem, authenticatedRequests, _ := newEmbeddedWebdavRemoteTestTarget(t, true, false, nil)
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	finalPath := "/audit/" + segment.ProducerId().String() + "/" + segment.FileName()

	require.NoError(t, target.Publish(context.Background(), segment))
	require.NoError(t, target.Publish(context.Background(), segment))
	require.Equal(t, content, readEmbeddedWebdavFile(t, fileSystem, finalPath))
	require.Equal(t, []string{segment.FileName()}, listEmbeddedWebdavDirectory(t, fileSystem, "/audit/"+segment.ProducerId().String()))
	target.password = "wrong-password"
	err = target.Publish(context.Background(), segment)
	require.True(t, bferrors.Permission.IsErr(err), err)
	require.ErrorContains(t, err, "401")
	target.password = "archive-password"

	file, err := fileSystem.OpenFile(context.Background(), finalPath, os.O_WRONLY|os.O_TRUNC, 0)
	require.NoError(t, err)
	_, err = file.Write([]byte("conflicting"))
	require.NoError(t, err)
	require.NoError(t, file.Close())
	err = target.Publish(context.Background(), segment)
	require.ErrorContains(t, err, "conflicts with local content")
	require.True(t, bferrors.System.IsErr(err))
	require.Equal(t, int32(7), authenticatedRequests.Load())
}

func TestWebdavRemoteTargetConcurrentPublicationIsAtomicAgainstEmbeddedServer(t *testing.T) {
	target, fileSystem, _, _ := newEmbeddedWebdavRemoteTestTarget(t, false, false, nil)
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
	succeeded := 0
	for range 2 {
		if publishErr := <-results; publishErr != nil {
			require.True(t, bferrors.Network.IsErr(publishErr), publishErr)
			require.ErrorContains(t, publishErr, "423")
		} else {
			succeeded++
		}
	}
	require.Positive(t, succeeded)
	require.NoError(t, target.Publish(context.Background(), segment))

	finalPath := "/audit/" + segment.ProducerId().String() + "/" + segment.FileName()
	require.Equal(t, content, readEmbeddedWebdavFile(t, fileSystem, finalPath))
	require.Equal(t, []string{segment.FileName()}, listEmbeddedWebdavDirectory(t, fileSystem, "/audit/"+segment.ProducerId().String()))
}

func TestWebdavRemoteTargetResolvesMoveConflictAgainstEmbeddedServer(t *testing.T) {
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	target, fileSystem, _, moveConflictInjected := newEmbeddedWebdavRemoteTestTarget(t, false, false, content)

	require.NoError(t, target.Publish(context.Background(), segment))
	require.True(t, moveConflictInjected.Load())
	finalPath := "/audit/" + segment.ProducerId().String() + "/" + segment.FileName()
	require.Equal(t, content, readEmbeddedWebdavFile(t, fileSystem, finalPath))
	require.Equal(t, []string{segment.FileName()}, listEmbeddedWebdavDirectory(t, fileSystem, "/audit/"+segment.ProducerId().String()))
}

func TestWebdavRemoteTargetCleansUpInterruptedUploadAgainstEmbeddedServer(t *testing.T) {
	target, fileSystem, _, _ := newEmbeddedWebdavRemoteTestTarget(t, false, false, nil)
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	segment.content = &webdavRemoteInterruptedReaderAt{content: content}

	err = target.Publish(context.Background(), segment)
	require.ErrorContains(t, err, "interrupted upload")
	finalPath := "/audit/" + segment.ProducerId().String() + "/" + segment.FileName()
	_, err = fileSystem.Stat(context.Background(), finalPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Empty(t, listEmbeddedWebdavDirectory(t, fileSystem, "/audit/"+segment.ProducerId().String()))
}

func TestWebdavRemoteTargetNeverMovesCorruptedTemporaryUpload(t *testing.T) {
	target, fileSystem, _, _ := newEmbeddedWebdavRemoteTestTarget(t, false, true, nil)
	segment := validRemoteTargetTestSegment()

	err := target.Publish(context.Background(), segment)
	require.ErrorContains(t, err, "conflicts with local content")
	finalPath := "/audit/" + segment.ProducerId().String() + "/" + segment.FileName()
	_, err = fileSystem.Stat(context.Background(), finalPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Empty(t, listEmbeddedWebdavDirectory(t, fileSystem, "/audit/"+segment.ProducerId().String()))
}

func TestWebdavRemoteTargetClassifiesFailuresWithoutRetry(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		err       error
		errorType bferrors.Type
	}{
		{"unauthorized", http.StatusUnauthorized, nil, bferrors.Permission},
		{"permission", http.StatusForbidden, nil, bferrors.Permission},
		{"network-status", http.StatusServiceUnavailable, nil, bferrors.Network},
		{"internal-server-error", http.StatusInternalServerError, nil, bferrors.Network},
		{"locked", http.StatusLocked, nil, bferrors.Network},
		{"configuration", http.StatusNotImplemented, nil, bferrors.Config},
		{"bad-gateway", http.StatusBadGateway, nil, bferrors.Network},
		{"unexpected-success", http.StatusNoContent, nil, bferrors.System},
		{"network-error", 0, webdavRemoteNetworkError{}, bferrors.Network},
		{"local-error", 0, goerrors.New("failure"), bferrors.System},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := classifyWebdavRemoteError(context.Background(), "test operation", test.status, test.err)
			require.True(t, test.errorType.IsErr(err), err)
		})
	}

	var calls atomic.Int32
	client := &webdavRemoteTestClient{do: func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return webdavRemoteResponse(http.StatusServiceUnavailable, ""), nil
	}}
	target := newWebdavRemoteTestTarget(t, client, false)
	err := target.Publish(context.Background(), validRemoteTargetTestSegment())
	require.True(t, bferrors.Network.IsErr(err), err)
	require.Equal(t, int32(1), calls.Load())
}

func TestNewWebdavRemoteTargetRendersCredentialsAndRefusesRedirects(t *testing.T) {
	t.Setenv("WEBDAV_TEST_USER", "archive-user")
	t.Setenv("WEBDAV_TEST_PASSWORD", "archive-password")
	conf := &configuration.AuditlogTargetWebdav{
		Endpoint: "https://dav.example.invalid/audit/",
		Username: template.MustNewString("{{ env `WEBDAV_TEST_USER` }}"),
		Password: template.MustNewString("{{ env `WEBDAV_TEST_PASSWORD` }}"),
	}
	raw, err := newWebdavRemoteTarget(context.Background(), RemoteTargetScope{Auditlog: "security", Target: "archive"}, conf)
	require.NoError(t, err)
	target := raw.(*webdavRemoteTarget)
	require.Equal(t, "archive-user", target.username)
	require.Equal(t, "archive-password", target.password)
	require.Equal(t, "/audit/", target.endpoint.Path)
	client := target.client.(*http.Client)
	require.ErrorIs(t, client.CheckRedirect(&http.Request{}, nil), http.ErrUseLastResponse)
	require.NoError(t, target.Close())
}

func TestWebdavRemoteTargetDoesNotForwardCredentialsOnRedirect(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		username, password, basic := request.BasicAuth()
		require.True(t, basic)
		require.Equal(t, "archive-user", username)
		require.Equal(t, "archive-password", password)
		response.Header().Set("Location", destination.URL+"/stolen")
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client := source.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	endpoint, err := url.Parse(source.URL + "/audit/")
	require.NoError(t, err)
	target, err := newWebdavRemoteTargetWithClient(endpoint, configuration.AuditlogTargetWebdavValues{
		Username: "archive-user", Password: "archive-password",
	}, client, nil)
	require.NoError(t, err)

	err = target.Publish(context.Background(), validRemoteTargetTestSegment())
	require.True(t, bferrors.Config.IsErr(err), err)
	require.NotContains(t, err.Error(), "archive-user")
	require.NotContains(t, err.Error(), "archive-password")
	require.Zero(t, redirected.Load())
}

func TestWebdavRemoteTargetContextAndClose(t *testing.T) {
	var calls atomic.Int32
	var closes atomic.Int32
	client := &webdavRemoteTestClient{do: func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return webdavRemoteResponse(http.StatusNotFound, ""), nil
	}}
	endpoint, err := url.Parse("https://dav.example.invalid/audit/")
	require.NoError(t, err)
	target, err := newWebdavRemoteTargetWithClient(endpoint, configuration.AuditlogTargetWebdavValues{}, client, func() { closes.Add(1) })
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	err = target.Publish(canceled, validRemoteTargetTestSegment())
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, calls.Load())
	require.NoError(t, target.Close())
	require.NoError(t, target.Close())
	require.Equal(t, int32(1), closes.Load())
	require.ErrorContains(t, target.Publish(context.Background(), validRemoteTargetTestSegment()), "closed")
}

func TestWebdavRemoteTargetCloseWaitsForPublish(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	client := &webdavRemoteTestClient{do: func(*http.Request) (*http.Response, error) {
		close(started)
		<-release
		return webdavRemoteResponse(http.StatusOK, "different"), nil
	}}
	target := newWebdavRemoteTestTarget(t, client, false)
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
	require.Error(t, <-published)
	require.NoError(t, <-closed)
}

func webdavRemoteResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func newWebdavRemoteTestTarget(t *testing.T, client webdavRemoteHTTPClient, authenticated bool) *webdavRemoteTarget {
	t.Helper()
	endpoint, err := url.Parse("https://dav.example.invalid/audit/")
	require.NoError(t, err)
	values := configuration.AuditlogTargetWebdavValues{}
	if authenticated {
		values.Username = "archive-user"
		values.Password = "archive-password"
	}
	target, err := newWebdavRemoteTargetWithClient(endpoint, values, client, nil)
	require.NoError(t, err)
	return target
}

func newEmbeddedWebdavRemoteTestTarget(t *testing.T, authenticated, corruptUploads bool, moveConflictContent []byte) (*webdavRemoteTarget, webdav.FileSystem, *atomic.Int32, *atomic.Bool) {
	t.Helper()
	fileSystem := webdav.NewMemFS()
	require.NoError(t, fileSystem.Mkdir(context.Background(), "/audit", 0o755))
	// x/net/webdav exercises the protocol but does not enforce If-None-Match on PUT;
	// the request-level test above verifies that our client still sends it.
	webdavHandler := &webdav.Handler{
		Prefix:     "/dav",
		FileSystem: fileSystem,
		LockSystem: webdav.NewMemLS(),
	}
	var authenticatedRequests atomic.Int32
	var moveConflictInjected atomic.Bool
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == webdavMethodMove && moveConflictContent != nil && moveConflictInjected.CompareAndSwap(false, true) {
			destination, parseErr := url.Parse(request.Header.Get("Destination"))
			if parseErr == nil {
				name := strings.TrimPrefix(destination.Path, webdavHandler.Prefix)
				if file, openErr := fileSystem.OpenFile(request.Context(), name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600); openErr == nil {
					_, _ = file.Write(moveConflictContent)
					_ = file.Close()
				}
			}
		}
		webdavHandler.ServeHTTP(response, request)
		if corruptUploads && request.Method == http.MethodPut {
			name := strings.TrimPrefix(request.URL.Path, webdavHandler.Prefix)
			if file, openErr := fileSystem.OpenFile(request.Context(), name, os.O_WRONLY|os.O_TRUNC, 0); openErr == nil {
				_, _ = file.Write([]byte("partial"))
				_ = file.Close()
			}
		}
	})
	values := configuration.AuditlogTargetWebdavValues{}
	if authenticated {
		values.Username = "archive-user"
		values.Password = "archive-password"
		authenticatedHandler := handler
		handler = http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			username, password, ok := request.BasicAuth()
			if !ok || username != values.Username || password != values.Password {
				response.Header().Set("WWW-Authenticate", `Basic realm="audit"`)
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			authenticatedRequests.Add(1)
			authenticatedHandler.ServeHTTP(response, request)
		})
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL + "/dav/audit/")
	require.NoError(t, err)
	target, err := newWebdavRemoteTargetWithClient(endpoint, values, server.Client(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, target.Close()) })
	return target, fileSystem, &authenticatedRequests, &moveConflictInjected
}

func readEmbeddedWebdavFile(t *testing.T, fileSystem webdav.FileSystem, name string) []byte {
	t.Helper()
	file, err := fileSystem.OpenFile(context.Background(), name, os.O_RDONLY, 0)
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	content, err := io.ReadAll(file)
	require.NoError(t, err)
	return content
}

func listEmbeddedWebdavDirectory(t *testing.T, fileSystem webdav.FileSystem, name string) []string {
	t.Helper()
	directory, err := fileSystem.OpenFile(context.Background(), name, os.O_RDONLY, 0)
	require.NoError(t, err)
	defer func() { require.NoError(t, directory.Close()) }()
	entries, err := directory.Readdir(-1)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
