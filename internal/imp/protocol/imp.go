package protocol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"

	log "github.com/echocat/slf4g"
	"github.com/things-go/go-socks5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

const (
	DefaultPort = 9687
)

type Imp struct {
	MasterPublicKey crypto.PublicKey
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
		Imp:      this,
		listener: NewMuxListener(tlsLn),
		socks5:   socks5.NewServer(socks5.WithLogger(log.GetLogger("socks5"))),
	}

	var wg sync.WaitGroup

	var rpcErr atomic.Pointer[error]
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := instance.serveRpc(instance.listener.Rpc()); err != nil {
			if !bnet.IsClosedError(err) && !errors.Is(err, http.ErrServerClosed) {
				rpcErr.Store(&err)
			}
		}
	}()

	var socksErr atomic.Pointer[error]
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := instance.serveSocks5(instance.listener.Socks5()); err != nil {
			if !bnet.IsClosedError(err) {
				socksErr.Store(&err)
			}
		}
	}()

	<-ctx.Done()
	if err := instance.listener.Close(); err != nil {
		return failf("cannot close listener: %v", err)
	}

	wg.Wait()
	if err := rpcErr.Load(); err != nil {
		return failf("problems while listening to rpc: %w", *err)
	}
	if err := socksErr.Load(); err != nil {
		return failf("problems while listening to socks5: %w", *err)
	}

	return nil
}

type imp struct {
	*Imp
	listener MuxListener
	socks5   *socks5.Server
}

func (this *imp) serveSocks5(ln net.Listener) error {
	defer common.IgnoreCloseError(ln)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		if err := this.socks5.ServeConn(conn); err != nil {
			log.GetLogger("socks5").WithError(err).Warn()
		}
	}
}

func (this *imp) serveRpc(ln net.Listener) error {
	ctx := context.Background()
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

	switch header.Method {
	case MethodEcho:
		return done(this.handleMethodEcho(ctx, &header, conn))
	case MethodKill:
		return done(this.handleMethodKill(ctx, &header, conn))
	case MethodExit:
		return done(this.handleMethodExit(ctx, &header, conn))
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
	cert, err := generateCertificateForPrivateKey("bifroest-imp", prv)
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
