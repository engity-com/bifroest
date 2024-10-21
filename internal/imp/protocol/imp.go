package protocol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strconv"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

const (
	DefaultPort = 9687
)

type Imp struct {
	MasterPublicKey crypto.PublicKey
	SessionId       session.Id
	Addr            string
	Logger          log.Logger
}

func (this *Imp) Serve(ctx context.Context) error {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.Network.Newf(msg, args...))
	}

	tlsConfig, err := this.createTlsConfig()
	if err != nil {
		return fail(err)
	}

	addr := this.getAddr()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return failf("cannot listen to %s: %v", addr, err)
	}

	tlsLn := tls.NewListener(ln, tlsConfig)

	instance := &imp{
		Imp: this,
	}

	go func() {
		<-ctx.Done()
		_ = tlsLn.Close()
	}()

	if err := instance.serveRpc(ctx, tlsLn); err != nil {
		if !bnet.IsClosedError(err) && !errors.Is(err, http.ErrServerClosed) {
			return failf("problems while listening to rpc: %w", err)
		}
	}

	return nil
}

type imp struct {
	*Imp
}

func (this *imp) serveRpc(ctx context.Context, ln net.Listener) error {
	defer common.IgnoreCloseError(ln)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}

		if err := this.serveRpcConn(ctx, conn); err != nil {
			log.GetLogger("rpc").WithError(err).Warn()
		}
	}
}

func (this *imp) serveRpcConn(ctx context.Context, plainConn net.Conn) (rErr error) {
	fail := func(err error) error {
		return err
	}
	done := func(err error) error {
		return err
	}
	conn := codec.GetPooledMsgPackConn(plainConn)
	defer common.KeepCloseError(&rErr, conn)

	var header Header
	if err := header.DecodeMsgPack(conn); err != nil {
		return fail(err)
	}
	l := this.logger().
		With("remote", plainConn.RemoteAddr()).
		With("method", header.Method).
		With("connectionId", header.ConnectionId)

	switch header.Method {
	case MethodEcho:
		return done(this.handleMethodEcho(ctx, &header, l, conn))
	case MethodKill:
		return done(this.handleMethodKill(ctx, &header, l, conn))
	case MethodExit:
		return done(this.handleMethodExit(ctx, &header, l, conn))
	case MethodTcpForward:
		return done(this.handleMethodTcpForward(ctx, &header, l, conn))
	case MethodNamedPipe:
		return done(this.handleMethodNamedPipe(ctx, &header, l, conn))
	default:
		return fail(errors.Network.Newf("unsupported method %v", header.Method))
	}
}

func (this *Imp) createTlsConfig() (*tls.Config, error) {
	fail := func(err error) (*tls.Config, error) {
		return nil, err
	}

	prv, err := this.generatePrivateKey()
	if err != nil {
		return fail(err)
	}
	cert, err := this.getOwnCertificate(prv)
	if err != nil {
		return fail(err)
	}

	verifier, err := peerVerifierForPublicKey(this.MasterPublicKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  prv.ToSdk(),
		}},
		VerifyPeerCertificate: verifier,
		MinVersion:            minTlsVersion,
		CipherSuites:          tlsCipherSuites,
		ClientAuth:            tls.RequireAnyClientCert,
	}, nil
}

func (this *Imp) generatePrivateKey() (crypto.PrivateKey, error) {
	req := crypto.KeyRequirement{
		Type: crypto.KeyTypeEd25519,
	}
	result, err := req.GenerateKey(nil)
	if err != nil {
		return nil, errors.System.Newf("cannot generate private key for imp: %w", err)
	}
	return result, nil
}

func (this *Imp) getOwnCertificate(prv crypto.PrivateKey) (*x509.Certificate, error) {
	cert, err := generateCertificateForPrivateKey("bifroest-imp", this.SessionId, prv)
	if err != nil {
		return nil, errors.System.Newf("cannot generate certificate for imp: %w", err)
	}
	return cert, nil
}

func (this *Imp) getAddr() string {
	if v := this.Addr; v != "" {
		return v
	}
	return ":" + strconv.Itoa(DefaultPort)
}

func (this *Imp) logger() log.Logger {
	result := this.Logger
	if result == nil {
		result = log.GetLogger("imp")
	}
	return result.
		With("sessionId", this.SessionId)
}
