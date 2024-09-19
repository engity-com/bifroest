package protocol

import (
	"context"
	gocrypto "crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"

	"github.com/engity-com/bifroest/pkg/codec"
)

type Master struct {
	PrivateKey gocrypto.Signer

	initOnce      sync.Once
	tlsDialers    sync.Pool
	socks5Dialers sync.Pool
}

type Ref interface {
	PublicKey() ssh.PublicKey
	EndpointAddr() string
}

func (this *Master) DialContext(ctx context.Context, ref Ref) (net.Conn, error) {
	fail := func(err error) (net.Conn, error) {
		return nil, err
	}

	dialer, err := this.getTlsDialerFor(ref)
	if err != nil {
		return fail(err)
	}
	defer this.releaseTlsDialer(dialer)

	return dialer.DialContext(ctx, "tcp", ref.EndpointAddr())
}

func (this *Master) DialContextWithMsgPack(ctx context.Context, ref Ref) (codec.MsgPackConn, error) {
	fail := func(err error) (codec.MsgPackConn, error) {
		return nil, err
	}

	conn, err := this.DialContext(ctx, ref)
	if err != nil {
		return fail(err)
	}
	return codec.GetPooledMsgPackConn(conn), nil
}

func (this *Master) init() (err error) {
	this.initOnce.Do(func() {
		var cert *x509.Certificate
		cert, err = this.getOwnCertificate()
		if err != nil {
			return
		}

		this.tlsDialers.New = func() any {
			return this.newTlsDialer(cert)
		}
		this.socks5Dialers.New = func() any {
			return this.newSocks5Dialer()
		}
	})
	return
}

func (this *Master) newTlsDialer(ownCertificate *x509.Certificate) *tls.Dialer {
	return &tls.Dialer{
		Config: this.basicTlsConfigFor(ownCertificate),
	}
}

func (this *Master) getTlsDialerFor(ref Ref) (*tls.Dialer, error) {
	fail := func(err error) (*tls.Dialer, error) {
		return nil, err
	}

	if err := this.init(); err != nil {
		return fail(err)
	}

	result := this.tlsDialers.Get().(*tls.Dialer)
	result.Config.VerifyPeerCertificate = peerVerifierForPublicKey(ref.PublicKey())
	return result, nil
}

func (this *Master) releaseTlsDialer(v *tls.Dialer) {
	v.Config.VerifyPeerCertificate = alwaysWaysPeerVerifier
	this.tlsDialers.Put(v)
}

func (this *Master) newSocks5Dialer() *socks5Dialer {
	result := socks5Dialer{
		master: this,
		ref:    nil,
	}
	result.dialerDialer.parent = &result

	if d, err := proxy.SOCKS5("<later>", "<later>", nil, &result.dialerDialer); err != nil {
		panic(err)
	} else {
		result.Dialer = d.(Dialer)
	}

	return &result
}

func (this *Master) getSocks5Dialer(ref Ref) (*socks5Dialer, error) {
	fail := func(err error) (*socks5Dialer, error) {
		return nil, err
	}

	if err := this.init(); err != nil {
		return fail(err)
	}

	result := this.socks5Dialers.Get().(*socks5Dialer)
	result.ref = ref
	return result, nil
}

func (this *Master) releaseSocks5Dialer(v *socks5Dialer) {
	v.ref = nil
	this.socks5Dialers.Put(v)
}

func (this *Master) basicTlsConfigFor(ownCertificate *x509.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{ownCertificate.Raw},
			PrivateKey:  this.PrivateKey,
		}},
		MinVersion:         minTlsVersion,
		CipherSuites:       tlsCipherSuites,
		InsecureSkipVerify: true,
	}
}

func (this *Master) getOwnCertificate() (*x509.Certificate, error) {
	fail := func(err error) (*x509.Certificate, error) {
		return nil, err
	}

	cert, err := generateCertificateForPrivateKey("bifroest-master", this.PrivateKey)
	if err != nil {
		return fail(err)
	}
	return cert, nil
}

type Dialer interface {
	proxy.ContextDialer
	proxy.Dialer
}

type socks5Dialer struct {
	Dialer

	master       *Master
	dialerDialer socks5DialerDialer
	ref          Ref
}

type socks5DialerDialer struct {
	parent *socks5Dialer
}

func (this *socks5DialerDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	if network != "<later>" || addr != "<later>" {
		panic("called from illegal stack position")
	}
	return this.parent.master.DialContext(ctx, this.parent.ref)
}

func (this *socks5DialerDialer) Dial(network string, addr string) (net.Conn, error) {
	return this.DialContext(context.Background(), network, addr)
}
