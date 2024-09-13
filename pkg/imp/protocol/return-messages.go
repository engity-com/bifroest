package protocol

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/formatter"
	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp/logger"
	"github.com/engity-com/bifroest/pkg/net"
)

const (
	LogConnectionIdFieldKey     = "connectionId"
	LogConnectionPartIdFieldKey = "connectionPartId"
)

var (
	valueFormatter = formatter.NewSimpleTextValue()
)

func newErrorReturnMessage(connectionId uuid.UUID, connectionPartId uint32, err error) *returnMessage {
	t := errors.System
	if ee, ok := errors.IsError(err); ok && ee != nil {
		t = ee.Type
	}
	return &returnMessage{
		connectionId:     connectionId,
		connectionPartId: connectionPartId,
		errorType:        t,
		error:            err.Error(),
	}
}

func newLogReturnMessage(connectionId uuid.UUID, connectionPartId uint32, event log.Event) (*returnMessage, error) {
	fds := map[string]any{}
	if err := event.ForEach(func(k string, v any) error {
		switch tv := v.(type) {
		case nil, string, []byte, int, int64, uint, uint64, bool, float32, float64, time.Duration, time.Time:
			fds[k] = v
		case log.CoreLogger:
			fds[k] = tv.GetName()
		case log.Provider:
			fds[k] = tv.GetName()
		default:
			fv, err := valueFormatter.FormatTextValue(v, nil)
			if err != nil {
				return err
			}
			fds[k] = fv
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &returnMessage{
		connectionId:     connectionId,
		connectionPartId: connectionPartId,
		logLevel:         event.GetLevel(),
		logFields:        fds,
	}, nil
}

type returnMessage struct {
	connectionId     uuid.UUID
	connectionPartId uint32

	errorType errors.Type
	error     string

	logLevel  level.Level
	logFields map[string]any
}

type returnMessageType uint8

const (
	returnMessageTypeError returnMessageType = iota
	returnMessageTypeLogEvent
)

func (this returnMessage) EncodeMsgpack(enc *msgpack.Encoder) error {
	if err := enc.EncodeBytes(this.connectionId[:]); err != nil {
		return err
	}
	if err := enc.EncodeUint32(this.connectionPartId); err != nil {
		return err
	}
	if this.errorType != 0 {
		if err := enc.EncodeUint8(uint8(returnMessageTypeError)); err != nil {
			return err
		}
		if err := enc.EncodeUint8(uint8(this.errorType)); err != nil {
			return err
		}
		if err := enc.EncodeString(this.error); err != nil {
			return err
		}
	} else {
		if err := enc.EncodeUint8(uint8(returnMessageTypeLogEvent)); err != nil {
			return err
		}
		if err := enc.EncodeUint16(uint16(this.logLevel)); err != nil {
			return err
		}
		if err := enc.Encode(this.logFields); err != nil {
			return err
		}
	}

	return nil
}

func (this *returnMessage) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	if v, err := dec.DecodeBytes(); err != nil {
		return err
	} else if err := this.connectionId.UnmarshalBinary(v); err != nil {
		return err
	}
	if this.connectionPartId, err = dec.DecodeUint32(); err != nil {
		return err
	}
	if mt, err := dec.DecodeUint8(); err != nil {
		return err
	} else if mt == uint8(returnMessageTypeError) {
		if v, err := dec.DecodeUint8(); err != nil {
			return err
		} else {
			this.errorType = errors.Type(v)
		}
		if this.error, err = dec.DecodeString(); err != nil {
			return err
		}
	} else if mt == uint8(returnMessageTypeLogEvent) {
		if v, err := dec.DecodeUint16(); err != nil {
			return err
		} else {
			this.logLevel = level.Level(v)
		}
		this.logFields = map[string]any{}
		if err = dec.Decode(&this.logFields); err != nil {
			return err
		}
	}
	return nil
}

func (this *Server) serveLoggingAndErrors(ctx context.Context, conn io.ReadWriteCloser, errs chan *errorEvent, lvl level.Level) {
	defer common.IgnoreCloseError(conn)
	logEvents := make(chan log.Event)
	defer close(logEvents)

	logProvider := logger.Provider{
		Level: lvl,
		Drain: func(e log.Event) {
			defer func() {
				_ = recover()
			}()
			logEvents <- e
		},
	}
	providerFacade := this.getLoggerProviderFacade()
	providerFacade.Set(&logProvider)
	defer providerFacade.Set(this.getDefaultLoggerProvider())

	enc := msgpack.NewEncoder(conn)

	for {
		select {
		case <-ctx.Done():
			return
		case logEvent := <-logEvents:
			var connectionId uuid.UUID
			if v, ok := logEvent.Get(LogConnectionIdFieldKey); ok {
				connectionId, _ = v.(uuid.UUID)
			}
			var connectionPartId uint32
			if v, ok := logEvent.Get(LogConnectionPartIdFieldKey); ok {
				connectionPartId, _ = v.(uint32)
			}
			payload, err := newLogReturnMessage(connectionId, connectionPartId, logEvent.Without(LogConnectionIdFieldKey, LogConnectionPartIdFieldKey))
			if err != nil {
				go func() {
					errs <- &errorEvent{connectionId, connectionPartId,
						errors.System.Newf("cannot create payload of log event: %w", err),
					}
				}()
			}
			if err := enc.Encode(payload); net.IsClosedError(err) {
				// If this does not work, we simply escape...
				return
			} else if err != nil {
				go func() {
					errs <- &errorEvent{connectionId, connectionPartId,
						errors.System.Newf("cannot encode payload of log event: %w", err),
					}
				}()
			}
		case err, ok := <-errs:
			if !ok {
				return
			}
			if err != nil {
				payload := newErrorReturnMessage(err.connectionId, err.connectionPartId, err.error)
				if err := enc.Encode(payload); net.IsClosedError(err) {
					// If this does not work, we simply escape...
					return
				} else if err != nil {
					panic(fmt.Errorf("unhandled error in the error handler: %w", err))
				}
			}
		}
	}
}

func (this *ClientSession) handleLoggingAndErrors(ctx context.Context, conn io.ReadWriteCloser) {
	defer common.IgnoreCloseError(conn)

	l := this.logger()

	dec := msgpack.NewDecoder(conn)

	for ctx.Err() == nil {
		var msg returnMessage
		if err := dec.Decode(&msg); this.parent.isClosedError(err) {
			// Bye!
			return
		} else if err != nil {
			l.WithError(err).Error("cannot decode return message")
			return
		}
		if msg.errorType > 0 {
			this.handleError(l, msg.connectionId, msg.connectionPartId, msg.errorType, msg.error)
		}
		if msg.logLevel > 0 {
			this.handleLogEvent(l, msg.connectionId, msg.connectionPartId, msg.logLevel, msg.logFields)
		}
	}
}

func (this *ClientSession) handleError(
	logger log.Logger,
	connectionId uuid.UUID, connectionPartId uint32,
	errorType errors.Type, error string,
) {
	err := errors.Error{
		Message: error,
		Type:    errorType,
	}
	if logger.IsDebugEnabled() {
		logger.
			WithError(&err).
			With("connectionId", connectionId).
			With("connectionPartId", connectionPartId).
			Debug("received error from")
	}

	this.errors.Store(connectionId, err)
}

func (this *ClientSession) PeekLastError(connectionPartId uint32) error {
	v, ok := this.errors.LoadAndDelete(connectionPartId)
	if !ok {
		return nil
	}
	return v.(error)
}

func (this *ClientSession) handleLogEvent(
	logger log.Logger,
	connectionId uuid.UUID, connectionPartId uint32,
	lvl level.Level, fields map[string]any,
) {
	loggerFieldKey := native.DefaultFieldKeysSpec.GetLogger()
	loggerFieldValue := fields[loggerFieldKey]
	delete(fields, loggerFieldKey)
	if loggerFieldValue != nil && loggerFieldValue != "" {
		fields["impLogger"] = loggerFieldValue
	}
	if !bytes.Equal(connectionId[:], uuid.Nil[:]) {
		fields["connectionId"] = connectionId
	}
	if connectionPartId > 0 {
		fields["connectionPartId"] = connectionPartId
	}
	event := logger.NewEvent(lvl, fields)
	logger.Log(event, 1)
}
