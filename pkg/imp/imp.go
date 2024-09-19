package imp

import (
	"context"
	"io"
	"net"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/imp/protocol"
	bsession "github.com/engity-com/bifroest/pkg/session"
)

func NewImp(ctx context.Context, version common.Version, conf *configuration.Imp) (Imp, error) {
	binaries, err := NewBinaries(ctx, version, conf)
	if err != nil {
		return nil, err
	}
	return &imp{
		Binaries: binaries,
	}, nil
}

type Imp interface {
	io.Closer
	BinaryProvider
	Connect(ctx context.Context, token []byte, sess bsession.Session, conn net.Conn) (Session, error)
	GetReconnectSignal(context.Context) (string, error)
}

type imp struct {
	*Binaries
	master protocol.Master
}

func (this *imp) Connect(ctx context.Context, token []byte, sess bsession.Session, conn net.Conn) (Session, error) {
	cs, err := this.master.Open(ctx, token, sess.Id(), conn)
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func (this *imp) GetReconnectSignal(_ context.Context) (string, error) {
	return "SIGINT", nil
}
