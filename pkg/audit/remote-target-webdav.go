package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	goerrors "errors"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	webdavMethodMkcol = "MKCOL"
	webdavMethodMove  = "MOVE"
)

var _ = registerPreparedRemoteTarget(
	func() configuration.AuditlogTargetV { return &configuration.AuditlogTargetWebdav{} },
	prepareWebdavRemoteTarget,
)

type webdavRemoteHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type webdavRemoteTarget struct {
	mutex    sync.RWMutex
	client   webdavRemoteHTTPClient
	endpoint *url.URL
	username string
	password string
	close    func()
	closed   bool
	closeErr error
}

func newWebdavRemoteTarget(ctx context.Context, _ RemoteTargetScope, conf *configuration.AuditlogTargetWebdav) (RemoteTarget, error) {
	target, _, _, err := prepareWebdavRemoteTarget(ctx, RemoteTargetScope{}, conf)
	return target, err
}

func prepareWebdavRemoteTarget(ctx context.Context, _ RemoteTargetScope, conf *configuration.AuditlogTargetWebdav) (RemoteTarget, time.Duration, remoteDeliveryDestinationFingerprint, error) {
	if conf == nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("nil WebDAV audit target configuration")
	}
	snapshot := *conf
	conf = &snapshot
	if err := conf.Validate(); err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("invalid WebDAV audit target configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, err
	}
	values, err := conf.Render(nil)
	if err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("cannot render WebDAV audit target configuration: %w", err)
	}
	endpoint, err := normalizedWebdavRemoteEndpoint(conf.Endpoint)
	if err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, err
	}
	timeout, fingerprint, err := webdavRemoteDeliveryTargetSettings(values, endpoint)
	if err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	bfcrypto.AdjustHttpTransportWithCaCerts(transport)
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	target, err := newWebdavRemoteTargetWithClient(endpoint, values, client, transport.CloseIdleConnections)
	if err != nil {
		transport.CloseIdleConnections()
	}
	return target, timeout, fingerprint, err
}

func newWebdavRemoteTargetWithClient(endpoint *url.URL, values configuration.AuditlogTargetWebdavValues, client webdavRemoteHTTPClient, close func()) (*webdavRemoteTarget, error) {
	if endpoint == nil {
		return nil, errors.Config.Newf("nil WebDAV endpoint")
	}
	if isNilRemoteValue(client) {
		return nil, errors.System.Newf("nil WebDAV HTTP client")
	}
	copyOfEndpoint := *endpoint
	return &webdavRemoteTarget{
		client: client, endpoint: &copyOfEndpoint, username: values.Username, password: values.Password, close: close,
	}, nil
}

func (this *webdavRemoteTarget) Publish(ctx context.Context, segment SealedSegment) error {
	this.mutex.RLock()
	defer this.mutex.RUnlock()
	if this.closed {
		return errors.System.Newf("WebDAV audit target is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	checksum, err := hashWebdavSegment(ctx, segment.Content())
	if err != nil {
		return err
	}
	collectionURL := appendWebdavURL(this.endpoint, true, segment.ProducerId().String())
	finalURL := appendWebdavURL(collectionURL, false, segment.FileName())
	exists, err := this.verifyObject(ctx, finalURL, segment.Size(), checksum, "existing audit segment")
	if err != nil || exists {
		return err
	}
	if err := this.ensureCollection(ctx, collectionURL); err != nil {
		return err
	}
	temporaryURL, err := newWebdavTemporaryURL(collectionURL)
	if err != nil {
		return err
	}
	cleanup, err := this.putTemporary(ctx, temporaryURL, segment)
	if err != nil {
		if cleanup {
			return goerrors.Join(err, this.cleanupTemporaryAfterFailure(ctx, temporaryURL))
		}
		return err
	}
	exists, err = this.verifyObject(ctx, temporaryURL, segment.Size(), checksum, "temporary audit segment")
	if err != nil {
		return goerrors.Join(err, this.cleanupTemporaryAfterFailure(ctx, temporaryURL))
	}
	if !exists {
		return goerrors.Join(errors.Network.Newf("temporary WebDAV audit segment disappeared after upload"), this.cleanupTemporaryAfterFailure(ctx, temporaryURL))
	}
	return this.moveTemporary(ctx, temporaryURL, finalURL, segment.Size(), checksum)
}

func hashWebdavSegment(ctx context.Context, content io.Reader) ([]byte, error) {
	if content == nil {
		return nil, errors.System.Newf("nil sealed audit segment content")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, contextReader{context: ctx, reader: content}); err != nil {
		return nil, errors.System.Newf("cannot hash sealed audit segment for WebDAV: %w", err)
	}
	return hasher.Sum(nil), nil
}

func appendWebdavURL(base *url.URL, trailingSlash bool, components ...string) *url.URL {
	result := *base
	escapedPath := strings.TrimSuffix(result.EscapedPath(), "/")
	result.Path = strings.TrimSuffix(result.Path, "/")
	for _, component := range components {
		result.Path += "/" + component
		escapedPath += "/" + url.PathEscape(component)
	}
	if trailingSlash {
		result.Path += "/"
		escapedPath += "/"
	}
	result.RawPath = escapedPath
	return &result
}

func newWebdavTemporaryURL(collectionURL *url.URL) (*url.URL, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, errors.System.Newf("cannot generate WebDAV temporary object name: %w", err)
	}
	return appendWebdavURL(collectionURL, false, ".bifroest-upload-"+hex.EncodeToString(random[:])+".tmp"), nil
}

func (this *webdavRemoteTarget) newRequest(ctx context.Context, method string, target *url.URL, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, errors.System.Newf("cannot create WebDAV %s request: %w", method, err)
	}
	if this.username != "" {
		request.SetBasicAuth(this.username, this.password)
	}
	return request, nil
}

func (this *webdavRemoteTarget) ensureCollection(ctx context.Context, collectionURL *url.URL) error {
	request, err := this.newRequest(ctx, webdavMethodMkcol, collectionURL, nil)
	if err != nil {
		return err
	}
	response, err := this.client.Do(request)
	if err != nil {
		return classifyWebdavRemoteError(ctx, "create audit segment collection", 0, err)
	}
	if response == nil {
		return errors.Network.Newf("WebDAV returned no response for create audit segment collection")
	}
	closeErr := closeWebdavResponse(response, "create audit segment collection")
	if response.StatusCode == http.StatusCreated || response.StatusCode == http.StatusMethodNotAllowed {
		return closeErr
	}
	return goerrors.Join(classifyWebdavRemoteError(ctx, "create audit segment collection", response.StatusCode, nil), closeErr)
}

func (this *webdavRemoteTarget) putTemporary(ctx context.Context, temporaryURL *url.URL, segment SealedSegment) (bool, error) {
	request, err := this.newRequest(ctx, http.MethodPut, temporaryURL, segment.Content())
	if err != nil {
		return false, err
	}
	request.ContentLength = segment.Size()
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("If-None-Match", "*")
	response, err := this.client.Do(request)
	if err != nil {
		return true, classifyWebdavRemoteError(ctx, "upload temporary audit segment", 0, err)
	}
	if response == nil {
		return true, errors.Network.Newf("WebDAV returned no response for upload temporary audit segment")
	}
	closeErr := closeWebdavResponse(response, "upload temporary audit segment")
	if response.StatusCode == http.StatusCreated {
		return closeErr != nil, closeErr
	}
	if response.StatusCode == http.StatusPreconditionFailed {
		return false, goerrors.Join(errors.Network.Newf("temporary WebDAV audit segment already exists"), closeErr)
	}
	return true, goerrors.Join(classifyWebdavRemoteError(ctx, "upload temporary audit segment", response.StatusCode, nil), closeErr)
}

func (this *webdavRemoteTarget) moveTemporary(ctx context.Context, temporaryURL, finalURL *url.URL, size int64, checksum []byte) error {
	request, err := this.newRequest(ctx, webdavMethodMove, temporaryURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Destination", finalURL.String())
	request.Header.Set("Overwrite", "F")
	response, err := this.client.Do(request)
	if err != nil {
		return goerrors.Join(classifyWebdavRemoteError(ctx, "publish audit segment", 0, err), this.cleanupTemporaryAfterFailure(ctx, temporaryURL))
	}
	if response == nil {
		return goerrors.Join(errors.Network.Newf("WebDAV returned no response for publish audit segment"), this.cleanupTemporaryAfterFailure(ctx, temporaryURL))
	}
	closeErr := closeWebdavResponse(response, "publish audit segment")
	if response.StatusCode == http.StatusCreated {
		return closeErr
	}
	cleanupErr := this.cleanupTemporaryAfterFailure(ctx, temporaryURL)
	if response.StatusCode != http.StatusPreconditionFailed {
		return goerrors.Join(classifyWebdavRemoteError(ctx, "publish audit segment", response.StatusCode, nil), closeErr, cleanupErr)
	}
	exists, verifyErr := this.verifyObject(ctx, finalURL, size, checksum, "existing audit segment")
	if verifyErr != nil {
		return goerrors.Join(verifyErr, closeErr, cleanupErr)
	}
	if !exists {
		verifyErr = errors.Network.Newf("existing WebDAV audit segment disappeared after MOVE conflict")
	}
	return goerrors.Join(verifyErr, closeErr, cleanupErr)
}

func (this *webdavRemoteTarget) verifyObject(ctx context.Context, objectURL *url.URL, size int64, expectedChecksum []byte, description string) (bool, error) {
	request, err := this.newRequest(ctx, http.MethodGet, objectURL, nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-cache, no-store")
	response, err := this.client.Do(request)
	if err != nil {
		return false, classifyWebdavRemoteError(ctx, "read "+description, 0, err)
	}
	if response == nil {
		return false, errors.Network.Newf("WebDAV returned no response for read %s", description)
	}
	if response.StatusCode == http.StatusNotFound {
		return false, closeWebdavResponse(response, "read "+description)
	}
	if response.StatusCode != http.StatusOK {
		return false, goerrors.Join(classifyWebdavRemoteError(ctx, "read "+description, response.StatusCode, nil), closeWebdavResponse(response, "read "+description))
	}
	if response.Body == nil {
		return false, errors.Network.Newf("WebDAV returned no content for %s", description)
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return false, goerrors.Join(errors.Config.Newf("WebDAV returned unsupported content encoding %q for %s", encoding, description), closeWebdavResponse(response, "read "+description))
	}
	conflict := func(message string, args ...any) error {
		return errors.System.Newf("WebDAV %s conflicts with local content: "+message, append([]any{description}, args...)...)
	}
	if response.ContentLength >= 0 && response.ContentLength != size {
		return false, goerrors.Join(conflict("size is %d instead of %d", response.ContentLength, size), closeWebdavResponse(response, "read "+description))
	}
	hasher := sha256.New()
	read, readErr := copyWebdavObject(ctx, hasher, response.Body, size+1, description)
	closeErr := closeWebdavResponse(response, "read "+description)
	if readErr != nil {
		return false, goerrors.Join(readErr, closeErr)
	}
	if read != size {
		return false, goerrors.Join(conflict("size is %d instead of %d", read, size), closeErr)
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), expectedChecksum) != 1 {
		return false, goerrors.Join(conflict("SHA-256 checksum differs"), closeErr)
	}
	return true, closeErr
}

func copyWebdavObject(ctx context.Context, target hash.Hash, source io.Reader, limit int64, description string) (int64, error) {
	read, err := io.Copy(target, contextReader{context: ctx, reader: io.LimitReader(source, limit)})
	if err != nil {
		return read, errors.Network.Newf("cannot read WebDAV %s: %w", description, err)
	}
	return read, nil
}

func (this *webdavRemoteTarget) cleanupTemporary(ctx context.Context, temporaryURL *url.URL) error {
	if ctx.Err() != nil {
		return nil
	}
	request, err := this.newRequest(ctx, http.MethodDelete, temporaryURL, nil)
	if err != nil {
		return err
	}
	response, err := this.client.Do(request)
	if err != nil {
		return classifyWebdavRemoteError(ctx, "remove temporary audit segment", 0, err)
	}
	if response == nil {
		return errors.Network.Newf("WebDAV returned no response for remove temporary audit segment")
	}
	closeErr := closeWebdavResponse(response, "remove temporary audit segment")
	if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusAccepted || response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusNotFound {
		return closeErr
	}
	return goerrors.Join(classifyWebdavRemoteError(ctx, "remove temporary audit segment", response.StatusCode, nil), closeErr)
}

func (this *webdavRemoteTarget) cleanupTemporaryAfterFailure(parent context.Context, temporaryURL *url.URL) error {
	ctx, cancel := newRemoteTargetCleanupContext(parent)
	defer cancel()
	return this.cleanupTemporary(ctx, temporaryURL)
}

func closeWebdavResponse(response *http.Response, operation string) error {
	if response == nil {
		return errors.Network.Newf("WebDAV returned no response for %s", operation)
	}
	if response.Body == nil {
		return nil
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	closeErr := response.Body.Close()
	if readErr != nil {
		readErr = errors.Network.Newf("cannot discard WebDAV response for %s: %w", operation, readErr)
	}
	if closeErr != nil {
		closeErr = errors.Network.Newf("cannot close WebDAV response for %s: %w", operation, closeErr)
	}
	return goerrors.Join(readErr, closeErr)
}

func classifyWebdavRemoteError(ctx context.Context, operation string, status int, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if goerrors.Is(err, context.Canceled) || goerrors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if err != nil {
		var networkError net.Error
		if goerrors.As(err, &networkError) {
			return errors.Network.Newf("cannot %s with WebDAV: %w", operation, err)
		}
		return errors.System.Newf("cannot %s with WebDAV: %w", operation, err)
	}
	statusError := func(kind errors.Type) error {
		return kind.Newf("cannot %s with WebDAV: unexpected HTTP status %d (%s)", operation, status, http.StatusText(status))
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusProxyAuthRequired:
		return statusError(errors.Permission)
	case status == http.StatusNotImplemented:
		return statusError(errors.Config)
	case status == http.StatusRequestTimeout || status == http.StatusLocked || status == http.StatusTooEarly ||
		status == http.StatusTooManyRequests || status == http.StatusInsufficientStorage || status >= 500:
		return statusError(errors.Network)
	case status >= 300 && status < 500:
		return statusError(errors.Config)
	default:
		return statusError(errors.System)
	}
}

func (this *webdavRemoteTarget) Close() error {
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
