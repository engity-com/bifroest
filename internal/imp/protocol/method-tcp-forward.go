package protocol

import (
	"context"
	gonet "net"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
)

type methodTcpForwardRequest struct {
	target net.HostPort
}

func (this methodTcpForwardRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodTcpForwardRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodTcpForwardRequest) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if b, err := this.target.MarshalText(); err != nil {
		return err
	} else if err := enc.EncodeBytes(b); err != nil {
		return err
	}
	return nil
}

func (this *methodTcpForwardRequest) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if b, err := dec.DecodeBytes(); err != nil {
		return err
	} else if err := this.target.UnmarshalText(b); err != nil {
		return err
	}
	return nil
}

type methodTcpForwardResponse struct {
	error error
}

func (this methodTcpForwardResponse) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodTcpForwardResponse) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodTcpForwardResponse) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := errors.EncodeMsgPack(this.error, enc); err != nil {
		return err
	}
	return nil
}

func (this *methodTcpForwardResponse) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if this.error, err = errors.DecodeMsgPack(dec); err != nil {
		return err
	}
	return nil
}

func (this *imp) handleMethodTcpForward(ctx context.Context, header *Header, logger log.Logger, conn codec.MsgPackConn) error {
	failCore := func(err error) error {
		return errors.Network.Newf("handling %v failed: %w", header.Method, err)
	}
	failConnectResponse := func(err error) error {
		wrapped := reWrapIfUserFacingNetworkErrors(err)

		if err := (methodTcpForwardResponse{error: wrapped}).EncodeMsgPack(conn); err != nil {
			return failCore(err)
		}
		logger.WithError(err).
			Info("port forwarding failed")
		return nil
	}

	var req methodTcpForwardRequest
	if err := req.DecodeMsgPack(conn); err != nil {
		return failCore(err)
	}
	logger = logger.With("target", req.target)

	var dialer gonet.Dialer
	target, err := dialer.DialContext(ctx, "tcp", req.target.String())
	if err != nil {
		return failConnectResponse(err)
	}
	defer common.IgnoreCloseError(target)

	if err := (methodTcpForwardResponse{}).EncodeMsgPack(conn); err != nil {
		return failCore(err)
	}

	nameOf := func(isL2r bool) string {
		if isL2r {
			return "source -> destination"
		}
		return "destination -> source"
	}

	if err := sys.FullDuplexCopy(ctx, target, conn, &sys.FullDuplexCopyOpts{
		OnStart: func() {
			logger.Debug("port forwarding started")
		},
		OnEnd: func(s2d, d2s int64, duration time.Duration, err error, wasInL2r *bool) {
			ld := logger.
				With("s2d", s2d).
				With("d2s", d2s).
				With("duration", duration)
			if wasInL2r != nil {
				ld = ld.With("direction", nameOf(*wasInL2r))
			}

			if err != nil {
				ld.WithError(err).Error("cannot successful handle port forwarding request; canceling...")
			} else {
				ld.Info("port forwarding finished")
			}
		},
		OnStreamEnd: func(isL2r bool, err error) {
			name := "source -> destination"
			if !isL2r {
				name = "destination -> source"
			}
			logger.WithError(err).Tracef("coping of %s done", name)
		}}); err != nil {
		return failCore(err)
	}

	return nil
}

func (this *Master) methodTcpForward(ctx context.Context, ref Ref, connectionId connection.Id, target net.HostPort) (gonet.Conn, error) {
	fail := func(err error) (gonet.Conn, error) {
		return nil, errors.Network.Newf("handling %v failed: %w", MethodTcpForward, err)
	}

	success := false
	conn, err := this.DialContextWithMsgPack(ctx, ref)
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreCloseErrorIfFalse(&success, conn)

	if err := (Header{MethodTcpForward, connectionId}).EncodeMsgPack(conn); err != nil {
		return fail(err)
	}

	if err := (methodTcpForwardRequest{target}).EncodeMsgPack(conn); err != nil {
		return fail(err)
	}

	var rsp methodTcpForwardResponse
	if err := rsp.DecodeMsgPack(conn); err != nil {
		return fail(err)
	}
	if err := rsp.error; err != nil {
		return fail(errors.AsRemoteError(err))
	}

	success = true
	return conn, err
}
