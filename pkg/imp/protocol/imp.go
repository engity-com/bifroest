package protocol

import (
	"context"
	gocrypto "crypto"
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
	MasterPublicKey gocrypto.PublicKey
	Addr            string
	Logger          log.Logger
}

func (this *Imp) Serve(_ context.Context) error {
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
	wg.Add(1)
	var rpcErr atomic.Pointer[error]
	go func() {
		defer wg.Done()
		if err := instance.serveRpc(instance.listener.Rpc()); err != nil {
			if !bnet.IsClosedError(err) && !errors.Is(err, http.ErrServerClosed) {
				rpcErr.Store(&err)
			}
		}
	}()

	if err := instance.serveSocks5(instance.listener.Socks5()); err != nil {
		return err
	}

	wg.Wait()
	if err := rpcErr.Load(); err != nil {
		return *err
	}

	return err
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
	if err := header.EncodeMsgPack(conn); err != nil {
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

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  prv,
		}},
		VerifyPeerCertificate: peerVerifierForPublicKey(this.MasterPublicKey),
		MinVersion:            minTlsVersion,
		CipherSuites:          tlsCipherSuites,
		ClientAuth:            tls.RequireAnyClientCert,
	}, nil
}

func (this *Imp) generatePrivateKey() (gocrypto.Signer, error) {
	req := crypto.KeyRequirement{
		Type: crypto.KeyTypeEd25519,
	}
	result, err := req.GenerateKey(nil)
	if err != nil {
		return nil, errors.System.Newf("cannot generate private key for IMP: %w", err)
	}
	return result, nil
}

func (this *Imp) getOwnCertificate(prv gocrypto.Signer) (*x509.Certificate, error) {
	cert, err := generateCertificateForPrivateKey("bifroest-imp", prv)
	if err != nil {
		return nil, errors.System.Newf("cannot generate certificate for IMP: %w", err)
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
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("imp")
}
