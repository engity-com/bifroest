package environment

import (
	"context"
	"io"
	"math"
	"strings"

	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

type dummy struct {
	repository *DummyRepository
	session    session.Session
}

func (this *dummy) Banner(req Request) (io.ReadCloser, error) {
	banner, err := this.repository.conf.Banner.Render(req)
	if err != nil {
		return nil, err
	}
	if banner == "" {
		return nil, nil
	}
	return io.NopCloser(strings.NewReader(banner)), nil
}

func (this *dummy) Run(t Task) (int, error) {
	exitCode, err := this.repository.conf.ExitCode.Render(t)
	if err != nil {
		return -1, err
	}
	if exitCode < math.MinInt || exitCode > math.MaxInt {
		return 1, nil
	}
	return int(exitCode), nil
}

func (this *dummy) IsPortForwardingAllowed(net.HostPort) (bool, error) {
	return false, nil
}

func (this *dummy) NewDestinationConnection(context.Context, net.HostPort) (io.ReadWriteCloser, error) {
	return nil, nil
}

func (this *dummy) Dispose(context.Context) (bool, error) {
	return false, nil
}

func (this *dummy) Close() error {
	return nil
}
