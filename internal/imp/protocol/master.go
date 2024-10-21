package protocol

import (
	"context"
	crypto2 "crypto"
	"crypto/tls"
	"crypto/x509"
	gonet "net"
	"sync"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

func NewMaster(_ context.Context, masterPrivateKey crypto.PrivateKey) (*Master, error) {
	fail := func(err error) (*Master, error) {
		return nil, err
	}

	result := &Master{
		PrivateKey: masterPrivateKey,
	}

	cert, err := generateCertificateForPrivateKey("bifroest-master", session.Id{}, masterPrivateKey)
	if err != nil {
		return fail(err)
	}
	result.tlsDialers.New = func() any {
		return &tls.Dialer{
			Config: result.basicTlsConfigFor(cert, masterPrivateKey.ToSdk()),
		}
	}

	return result, nil
}

type Master struct {
	PrivateKey crypto.PrivateKey

	tlsDialers sync.Pool
}

type Ref interface {
	SessionId() session.Id
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
	} else if sessionId := ref.SessionId(); !sessionId.IsZero() {
		result.Config.VerifyPeerCertificate = peerVerifierForSessionId(sessionId)
	} else {
		return nil, nil, errors.System.Newf("the imp ref provider neither a publicKey nor a sessionId")
	}
	return result, func() {
		result.Config.VerifyPeerCertificate = alwaysRejectPeerVerifier
		this.tlsDialers.Put(result)
	}, nil
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
