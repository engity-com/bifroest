package protocol

import (
	"io"

	log "github.com/echocat/slf4g"
	"github.com/google/uuid"
	"github.com/xtaci/smux"
)

type Conn interface {
	io.ReadWriter
	Id() uuid.UUID
	PartId() uint32
	Logger(context string) log.Logger
}

type conn struct {
	logProvider log.Provider
	*smux.Stream
	id        uuid.UUID
	sessionId uuid.UUID
}

func (this *conn) Id() uuid.UUID {
	return this.id
}

func (this *conn) SessionId() uuid.UUID {
	return this.sessionId
}

func (this *conn) PartId() uint32 {
	return this.Stream.ID()
}

func (this *conn) Logger(context string) log.Logger {
	return this.logProvider.GetLogger(context).
		With(LogConnectionIdFieldKey, this.Id()).
		With(LogConnectionPartIdFieldKey, this.PartId())
}
