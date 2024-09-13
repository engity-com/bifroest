package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"strings"

	"github.com/echocat/slf4g/level"
	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/bcrypt"

	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	handshakeMagic         = []byte{1, 2, 'E', 'n', 'g', 'B', 'f', 'r', 3}
	handshakeChallengeSeed = []byte{246, 225, 194, 6, 201, 185, 80, 23, 134, 152, 81, 69}

	ErrHandshakeFailed           = errors.Network.Newf("handshake failed")
	ErrHandshakeProtocolMismatch = errors.Network.Newf("handshake protocol mismatch")
	ErrIllegalMagic              = errors.Network.Newf("illegal magic")
	ErrIllegalVersion            = errors.Network.Newf("illegal version")
)

func newHandshakeRequest(token []byte, lvl level.Level, sessionId uuid.UUID) (r *handshakeRequest, err error) {
	r = &handshakeRequest{
		version:   CurrentVersion,
		challenge: make([]byte, 24),
		logLevel:  lvl,
		sessionId: sessionId,
	}
	if _, err = rand.Read(r.challenge); err != nil {
		return nil, err
	}
	if r.tokenHash, err = bcrypt.GenerateFromPassword(token, bcrypt.DefaultCost); err != nil {
		return nil, err
	}

	return r, nil
}

type handshakeRequest struct {
	version   Version
	tokenHash []byte
	challenge []byte
	logLevel  level.Level
	sessionId uuid.UUID
}

func (this handshakeRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	if this.version != CurrentVersion {
		return ErrIllegalVersion
	}
	if err := enc.EncodeBytes(handshakeMagic); err != nil {
		return err
	}
	if err := enc.Encode(this.version); err != nil {
		return err
	}
	if err := enc.EncodeBytes(this.tokenHash); err != nil {
		return err
	}
	if err := enc.EncodeBytes(this.challenge); err != nil {
		return err
	}
	if err := enc.EncodeUint16(uint16(this.logLevel)); err != nil {
		return err
	}
	if err := enc.EncodeBytes(this.sessionId[:]); err != nil {
		return err
	}
	return nil
}

func (this *handshakeRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	if v, err := dec.DecodeBytes(); err != nil {
		return err
	} else if !bytes.Equal(v, handshakeMagic) {
		return ErrIllegalMagic
	}
	if err := dec.Decode(&this.version); err != nil {
		return err
	} else if this.version != CurrentVersion {
		return ErrIllegalVersion
	}
	if this.tokenHash, err = dec.DecodeBytes(); err != nil {
		return err
	}
	if this.challenge, err = dec.DecodeBytes(); err != nil {
		return err
	}
	if v, err := dec.DecodeUint16(); err != nil {
		return err
	} else {
		this.logLevel = level.Level(v)
	}
	if v, err := dec.DecodeBytes(); err != nil {
		return err
	} else if err := this.sessionId.UnmarshalBinary(v); err != nil {
		return err
	}
	return nil
}

func (this handshakeRequest) validate(expectedToken []byte) (bool, error) {
	if err := bcrypt.CompareHashAndPassword(this.tokenHash, expectedToken); errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func newHandshakeResponse(challenge []byte) *handshakeResponse {
	return &handshakeResponse{
		challengeResponse: challengeResponseOf(challenge),
	}
}

type handshakeResponse struct {
	challengeResponse []byte
}

func (this handshakeResponse) EncodeMsgpack(enc *msgpack.Encoder) error {
	if err := enc.EncodeBytes(this.challengeResponse); err != nil {
		return err
	}
	return nil
}

func (this *handshakeResponse) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	if this.challengeResponse, err = dec.DecodeBytes(); err != nil {
		return err
	}
	return nil
}

func (this handshakeResponse) validate(challenge []byte) (bool, error) {
	if !bytes.Equal(this.challengeResponse, challengeResponseOf(challenge)) {
		return false, nil
	}
	return true, nil
}

func challengeResponseOf(challenge []byte) []byte {
	hash := sha1.New()
	hash.Write(handshakeChallengeSeed)
	hash.Write(challenge)
	return hash.Sum(nil)
}

func handleHandshakeFromServerSide(expectedToken []byte, conn io.ReadWriter) (logLevel level.Level, sessionId uuid.UUID, _ error) {
	fail := func(err error) (level.Level, uuid.UUID, error) {
		tErr := err
		for tErr == nil {
			if strings.HasPrefix(tErr.Error(), "msgpack: ") {
				return 0, uuid.UUID{}, errors.Network.Newf("%w: %v", ErrHandshakeProtocolMismatch, err)
			}
			ue, ok := err.(interface{ Unwrap() error })
			if !ok {
				break
			}
			tErr = ue.Unwrap()
		}
		return 0, uuid.UUID{}, errors.Network.Newf("%v: %w", ErrHandshakeFailed, err)
	}
	reject := func() (level.Level, uuid.UUID, error) {
		return 0, uuid.UUID{}, ErrHandshakeProtocolMismatch
	}

	var req handshakeRequest
	dec := msgpack.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		return fail(err)
	}
	if ok, err := req.validate(expectedToken); err != nil {
		return fail(err)
	} else if !ok {
		return reject()
	}

	rsp := newHandshakeResponse(req.challenge)
	enc := msgpack.NewEncoder(conn)
	if err := enc.Encode(rsp); err != nil {
		return fail(err)
	}

	return req.logLevel, req.sessionId, nil
}

func handleHandshakeFromClientSide(token []byte, lvl level.Level, sessionId uuid.UUID, conn io.ReadWriter) error {
	fail := func(err error) error {
		tErr := err
		for tErr == nil {
			if strings.HasPrefix(tErr.Error(), "msgpack: ") {
				return errors.Network.Newf("%w: %v", ErrHandshakeProtocolMismatch, err)
			}
			ue, ok := err.(interface{ Unwrap() error })
			if !ok {
				break
			}
			tErr = ue.Unwrap()
		}
		return errors.Network.Newf("%v: %w", ErrHandshakeFailed, err)
	}
	reject := func() error {
		return ErrHandshakeProtocolMismatch
	}

	req, err := newHandshakeRequest(token, lvl, sessionId)
	if err != nil {
		return fail(err)
	}
	enc := msgpack.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return fail(err)
	}

	var buffer bytes.Buffer
	var rsp handshakeResponse
	dec := msgpack.NewDecoder(io.TeeReader(conn, &buffer))
	if err := dec.Decode(&rsp); err != nil {
		return fail(err)
	}
	if ok, err := rsp.validate(req.challenge); err != nil {
		return fail(err)
	} else if !ok {
		return reject()
	}

	return nil
}

var smuxConfig = func() *smux.Config {
	result := smux.DefaultConfig()
	result.Version = 2
	return result
}()
