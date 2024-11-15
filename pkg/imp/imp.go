package imp

import (
	"context"
	"io"
	gonet "net"

	"github.com/engity-com/bifroest/internal/imp/protocol"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
)

const (
	EnvVarMasterPublicKey = "BIFROEST_MASTER_PUBLIC_KEY"

	DefaultInitPathUnix    = `/var/lib/engity/bifroest/init`
	DefaultInitPathWindows = `C:\ProgramData\Engity\Bifroest\init`
)

var (
	ErrNoSuchProcess = protocol.ErrNoSuchProcess
)

type Ref interface {
	SessionId() session.Id
	PublicKey() crypto.PublicKey
	Dial(context.Context) (gonet.Conn, error)
}

func NewImp(ctx context.Context, bifroestPrivateKey crypto.PrivateKey) (Imp, error) {
	master, err := protocol.NewMaster(ctx, bifroestPrivateKey)
	if err != nil {
		return nil, err
	}
	return &imp{
		master: master,
	}, nil
}

type Imp interface {
	io.Closer
	Open(context.Context, Ref) (Session, error)
	GetMasterPublicKey() (crypto.PublicKey, error)
}

type imp struct {
	master *protocol.Master
}

func (this *imp) Open(ctx context.Context, ref Ref) (Session, error) {
	cs, err := this.master.Open(ctx, ref)
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func (this *imp) GetMasterPublicKey() (crypto.PublicKey, error) {
	return this.master.PrivateKey.PublicKey(), nil
}

func (this *imp) Close() error {
	return nil
}
