package protocol

import (
	"context"
	crypto2 "crypto"
	"crypto/tls"
	"crypto/x509"
	gonet "net"
	"sync"

	"golang.org/x/net/proxy"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/net"
)

func NewMaster(_ context.Context, masterPrivateKey crypto.PrivateKey) (*Master, error) {
	fail := func(err error) (*Master, error) {
		return nil, err
	}

	result := &Master{
		PrivateKey: masterPrivateKey,
	}

	cert, err := generateCertificateForPrivateKey("bifroest-master", masterPrivateKey)
	if err != nil {
		return fail(err)
	}
	result.tlsDialers.New = func() any {
		return &tls.Dialer{
			Config: result.basicTlsConfigFor(cert, masterPrivateKey.ToSdk()),
		}
	}

	result.socks5Dialers.New = func() any {
		s5d := &socks5Dialer{
			master: result,
			ref:    nil,
		}
		s5d.dialerDialer.parent = s5d

		if d, err := proxy.SOCKS5("<later>", "<later>", nil, &s5d.dialerDialer); err != nil {
			panic(err)
		} else {
			s5d.Dialer = d.(Dialer)
		}

		return s5d
	}

	return result, nil
}

type Master struct {
	PrivateKey crypto.PrivateKey

	tlsDialers    sync.Pool
	socks5Dialers sync.Pool
}

type Ref interface {
	PublicKey() crypto.PublicKey
	EndpointAddr() net.HostPort
}

func (this *Master) Open(_ context.Context, ref Ref) (*MasterSession, error) {
	return &MasterSession{
		parent: this,
		ref:    ref,
	}, nil
}

func (this *Master) DialContext(ctx context.Context, ref Ref) (gonet.Conn, error) {
	dialer, releaser, err := this.tlsDialerFor(ref)
	if err != nil {
		return nil, err
	}
	defer releaser()

	return dialer.DialContext(ctx, "tcp", ref.EndpointAddr().String())
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

func (this *Master) tlsDialerFor(ref Ref) (_ *tls.Dialer, releaser func(), _ error) {
	result := this.tlsDialers.Get().(*tls.Dialer)

	if pub := ref.PublicKey(); pub != nil {
		verifier, err := peerVerifierForPublicKey(pub)
		if err != nil {
			return nil, nil, err
		}
		result.Config.VerifyPeerCertificate = verifier
	} else {
		result.Config.VerifyPeerCertificate = alwaysAcceptPeerVerifier
	}
	return result, func() {
		result.Config.VerifyPeerCertificate = alwaysRejectPeerVerifier
		this.tlsDialers.Put(result)
	}, nil
}

func (this *Master) socks5DialerFor(ref Ref) (_ *socks5Dialer, releaser func()) {
	result := this.socks5Dialers.Get().(*socks5Dialer)
	result.ref = ref
	return result, func() {
		result.ref = nil
		this.socks5Dialers.Put(result)
	}
}

func (this *Master) basicTlsConfigFor(ownCertificate *x509.Certificate, sdk crypto2.Signer) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{ownCertificate.Raw},
			PrivateKey:  sdk,
		}},
		MinVersion:         minTlsVersion,
		CipherSuites:       tlsCipherSuites,
		InsecureSkipVerify: true,
	}
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

func (this *socks5DialerDialer) DialContext(ctx context.Context, network string, addr string) (gonet.Conn, error) {
	if network != "<later>" || addr != "<later>" {
		panic("called from illegal stack position")
	}
	return this.parent.master.DialContext(ctx, this.parent.ref)
}

func (this *socks5DialerDialer) Dial(network string, addr string) (gonet.Conn, error) {
	return this.DialContext(context.Background(), network, addr)
}
