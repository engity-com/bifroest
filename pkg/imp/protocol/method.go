package protocol

import (
	"fmt"
	"io"
	"net"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
)

type Method uint8

const (
	MethodEcho Method = iota
	MethodDirectTcp
	MethodAgentForward
	MethodKill
	MethodExit
)

var (
	ErrIllegalMethod = errors.System.Newf("Illegal protocol method")
)

func (this *Method) Read(from io.Reader) error {
	buf := make([]byte, 1)
	if n, err := from.Read(buf); err != nil {
		return err
	} else if n != 1 {
		return io.ErrUnexpectedEOF
	}
	candidate := Method(buf[0])
	if err := candidate.Validate(); err != nil {
		return err
	}
	*this = candidate
	return nil
}

func (this Method) Write(to io.Writer) error {
	if err := this.Validate(); err != nil {
		return err
	}
	if n, err := to.Write([]byte{byte(this)}); err != nil {
		return err
	} else if n != 1 {
		return io.ErrShortWrite
	}
	return nil
}

func (this Method) String() string {
	v, ok := protocolMethodToString[this]
	if !ok {
		return fmt.Sprintf("illegal-protocol-method-%d", this)
	}
	return v
}

func (this Method) Validate() error {
	_, ok := protocolMethodToString[this]
	if !ok {
		return errors.System.Newf("%w: %d", ErrIllegalMethod, this)
	}
	return nil
}

var (
	stringToProtocolMethod = map[string]Method{
		"echo":         MethodEcho,
		"directTcp":    MethodDirectTcp,
		"agentForward": MethodAgentForward,
		"kill":         MethodKill,
		"exit":         MethodExit,
	}
	protocolMethodToString = func(in map[string]Method) map[Method]string {
		result := make(map[Method]string, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(stringToProtocolMethod)
)

func (this *ClientSession) doAndReturn(method Method, connectionId uuid.UUID, action func(net.Conn) error) (_ net.Conn, rErr error) {
	var connectionPartId uint32
	defer func() {
		if connectionPartId > 0 {
			if err := this.PeekLastError(connectionPartId); err != nil {
				rErr = err
			}
		}
	}()

	fail := func(err error) (net.Conn, error) {
		return nil, err
	}

	success := false
	stream, err := this.session.OpenStream()
	if err != nil {
		return fail(err)
	}
	defer common.DoOnFailureIgnore(&success, stream.Close)
	connectionPartId = stream.ID()

	if _, err := stream.Write(connectionId[:]); err != nil {
		return fail(err)
	}
	if err := method.Write(stream); err != nil {
		return fail(err)
	}
	if err := action(stream); err != nil {
		return fail(err)
	}

	success = true
	return stream, nil
}

func (this *ClientSession) do(method Method, connectionId uuid.UUID, action func(net.Conn) error) error {
	conn, err := this.doAndReturn(method, connectionId, action)
	if err != nil {
		return err
	}
	defer common.IgnoreCloseError(conn)
	return nil
}
