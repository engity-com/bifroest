package kubernetes

import (
	"context"
	"fmt"
	"io"
	gonet "net"
	"net/http"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrPodNotFound      = fmt.Errorf("pod not found")
	ErrEndpointNotFound = fmt.Errorf("endpoint not found")
)

func (this *client) DialPod(ctx context.Context, namespace, name, port string) (gonet.Conn, error) {
	fail := func(err error) (gonet.Conn, error) {
		return nil, err
	}

	clientSet, err := this.ClientSet()
	if err != nil {
		return fail(err)
	}

	return this.dial(
		ctx,
		clientSet.CoreV1().RESTClient(),
		schema.GroupVersionKind{
			Version: "v1",
			Kind:    "pod",
		},
		namespace, name,
		port,
	)

}

func (this *client) dial(ctx context.Context, restClient rest.Interface, gvk schema.GroupVersionKind, namespace, name, port string) (gonet.Conn, error) {
	fail := func(err error) (gonet.Conn, error) {
		return nil, err
	}

	req := restClient.Post().
		Resource(gvk.Kind + "s").
		Namespace(namespace).
		Name(name).
		SubResource("portforward")

	transport, upgrader, err := spdy.RoundTripperFor(this.RestConfig())
	if err != nil {
		return fail(err)
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", req.URL())

	success := false
	rawConn, _, err := dialer.Dial(portforward.PortForwardProtocolV1Name)
	if err != nil {
		var statusErr kerrors.APIStatus
		if errors.As(err, &statusErr) && statusErr.Status().Reason == metav1.StatusReasonNotFound {
			return fail(ErrEndpointNotFound)
		}
		if strings.HasPrefix(err.Error(), "unable to upgrade connection: pod not found") {
			return fail(ErrPodNotFound)
		}
		return fail(err)
	}
	defer common.IgnoreCloseErrorIfFalse(&success, rawConn)

	headers := http.Header{}
	headers.Set(v1.StreamType, v1.StreamTypeError)
	headers.Set(v1.PortHeader, port)
	headers.Set(v1.PortForwardRequestIDHeader, "1")

	errorStream, err := rawConn.CreateStream(headers)
	if err != nil {
		return nil, errors.Network.Newf("error creating err stream: %w", err)
	}
	defer func() {
		if !success {
			rawConn.RemoveStreams(errorStream)
		}
	}()
	defer common.IgnoreCloseErrorIfFalse(&success, errorStream)

	headers.Set(v1.StreamType, v1.StreamTypeData)
	dataStream, err := rawConn.CreateStream(headers)
	if err != nil {
		return nil, errors.Network.Newf("error creating data stream: %w", err)
	}
	defer func() {
		if !success {
			rawConn.RemoveStreams(dataStream)
		}
	}()
	defer common.IgnoreCloseErrorIfFalse(&success, dataStream)

	result := &httpstreamConn{
		delegate:       rawConn,
		port:           port,
		errCh:          make(chan error),
		err:            errorStream,
		data:           dataStream,
		ownerOvk:       gvk,
		ownerNamespace: namespace,
		ownerName:      name,
	}
	go result.watchErr(ctx)

	success = true
	return result, nil
}

type httpstreamConn struct {
	delegate       httpstream.Connection
	errCh          chan error
	data, err      httpstream.Stream
	port           string
	ownerOvk       schema.GroupVersionKind
	ownerNamespace string
	ownerName      string
}

func (this *httpstreamConn) watchErr(ctx context.Context) {
	// This should only return if an err comes back.
	bs, err := io.ReadAll(this.err)
	if err != nil {
		select {
		case <-ctx.Done():
		case this.errCh <- errors.Network.Newf("error during read: %w", err):
		}
	}
	if len(bs) > 0 {
		select {
		case <-ctx.Done():
		case this.errCh <- errors.Network.Newf("error during read: %s", string(bs)):
		}
	}
}

func (this *httpstreamConn) Read(b []byte) (n int, err error) {
	select {
	case err := <-this.errCh:
		return 0, err
	default:
		return this.data.Read(b)
	}
}

func (this *httpstreamConn) Write(b []byte) (n int, err error) {
	select {
	case err := <-this.errCh:
		return 0, err
	default:
		return this.data.Write(b)
	}
}

func (this *httpstreamConn) Close() (rErr error) {
	defer common.KeepCloseError(&rErr, this.delegate)
	defer this.delegate.RemoveStreams(this.data, this.err)
	defer common.KeepCloseError(&rErr, this.err)
	defer common.KeepCloseError(&rErr, this.data)

	select {
	case err := <-this.errCh:
		return err
	default:
		return nil
	}
}

func (this *httpstreamConn) LocalAddr() gonet.Addr {
	return httpstreamAddr("local")
}

func (this *httpstreamConn) RemoteAddr() gonet.Addr {
	return httpstreamAddr(fmt.Sprintf("%v/%s/%s:%s",
		this.ownerOvk,
		this.ownerNamespace,
		this.ownerName,
		this.port,
	))
}

func (this *httpstreamConn) SetDeadline(t time.Time) error {
	this.delegate.SetIdleTimeout(time.Until(t))
	return nil
}

func (this *httpstreamConn) SetReadDeadline(t time.Time) error {
	this.delegate.SetIdleTimeout(time.Until(t))
	return nil
}

func (this *httpstreamConn) SetWriteDeadline(t time.Time) error {
	this.delegate.SetIdleTimeout(time.Until(t))
	return nil
}

type httpstreamAddr string

func (f httpstreamAddr) Network() string {
	return "k8s-api"
}

func (f httpstreamAddr) String() string {
	return string(f)
}
