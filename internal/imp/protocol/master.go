package protocol

import (
	"context"
	gocrypto "crypto"
	"crypto/tls"
	"crypto/x509"
	gonet "net"
	"sync"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
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
	result.tlsConfigs.New = func() any {
		return result.basicTlsConfigFor(cert, masterPrivateKey.ToSdk())
	}

	return result, nil
}

type Master struct {
	PrivateKey crypto.PrivateKey

	tlsConfigs sync.Pool
}

type Ref interface {
	SessionId() session.Id
	PublicKey() crypto.PublicKey
	Dial(context.Context) (gonet.Conn, error)
}

func (this *Master) Open(_ context.Context, ref Ref) (*MasterSession, error) {
	return &MasterSession{
		parent: this,
		ref:    ref,
	}, nil
}

func (this *Master) DialContext(ctx context.Context, ref Ref) (gonet.Conn, error) {
	tlsConfig, releaser, err := this.tlsConfigFor(ref)
	if err != nil {
		return nil, err
	}
	defer releaser()

	success := false
	rawConn, err := ref.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer common.IgnoreCloseErrorIfFalse(&success, rawConn)

	conn := tls.Client(rawConn, tlsConfig)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	success = true
	return conn, nil
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

func (this *Master) tlsConfigFor(ref Ref) (_ *tls.Config, releaser func(), _ error) {
	result := this.tlsConfigs.Get().(*tls.Config)

	if pub := ref.PublicKey(); pub != nil {
		verifier, err := peerVerifierForPublicKey(pub)
		if err != nil {
			return nil, nil, err
		}
		result.VerifyPeerCertificate = verifier
	} else if sessionId := ref.SessionId(); !sessionId.IsZero() {
		result.VerifyPeerCertificate = peerVerifierForSessionId(sessionId)
	} else {
		return nil, nil, errors.System.Newf("the imp ref provider neither a publicKey nor a sessionId")
	}
	return result, func() {
		result.VerifyPeerCertificate = alwaysRejectPeerVerifier
		this.tlsConfigs.Put(result)
	}, nil
}

func (this *Master) basicTlsConfigFor(ownCertificate *x509.Certificate, sdk gocrypto.Signer) *tls.Config {
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
