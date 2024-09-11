package imp

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

var stdinoutConnection = &ConnectionAdapter{
	In:     os.Stdin,
	Out:    os.Stdout,
	Local:  StringAddr("stdinout"),
	Remote: StringAddr("stdinout"),
}

type ConnectionAdapter struct {
	In  io.Reader
	Out io.Writer

	Local  net.Addr
	Remote net.Addr
}

func (this *ConnectionAdapter) Read(b []byte) (n int, err error) {
	return this.In.Read(b)
}

func (this *ConnectionAdapter) Write(b []byte) (n int, err error) {
	return this.Out.Write(b)
}

func (this *ConnectionAdapter) Close() (rErr error) {
	defer func() {
		if c, ok := this.In.(io.Closer); ok {
			if err := c.Close(); err != nil && rErr == nil {
				rErr = err
			}
		}
	}()
	defer func() {
		if c, ok := this.Out.(io.Closer); ok {
			if err := c.Close(); err != nil && rErr == nil {
				rErr = err
			}
		}
	}()
	return nil
}

func (this *ConnectionAdapter) LocalAddr() net.Addr {
	if v := this.Local; v != nil {
		return v
	}
	return filesConnectionAddrV
}

func (this *ConnectionAdapter) RemoteAddr() net.Addr {
	if v := this.Remote; v != nil {
		return v
	}
	return filesConnectionAddrV
}

func (this *ConnectionAdapter) SetDeadline(time.Time) error {
	return fmt.Errorf("SetDeadline not supported")
}

func (this *ConnectionAdapter) SetReadDeadline(time.Time) error {
	return fmt.Errorf("SetReadDeadline not supported")
}

func (this *ConnectionAdapter) SetWriteDeadline(time.Time) error {
	return fmt.Errorf("SetWriteDeadline not supported")
}

var filesConnectionAddrV = StringAddr("pipe")

type StringAddr string

func (this StringAddr) Network() string { return string(this) }
func (this StringAddr) String() string  { return this.Network() }
