package imp

import (
	"context"
	"io"

	"github.com/engity-com/bifroest/internal/imp/protocol"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

var (
	ErrNoSuchProcess = protocol.ErrNoSuchProcess
)

type Ref interface {
	PublicKey() crypto.PublicKey
	EndpointAddr() net.HostPort
}

func NewImp(ctx context.Context, version common.Version, bifroestPrivateKey crypto.PrivateKey, conf *configuration.Imp) (Imp, error) {
	binaries, err := NewBinaries(ctx, version, conf)
	if err != nil {
		return nil, err
	}
	master, err := protocol.NewMaster(ctx, bifroestPrivateKey)
	if err != nil {
		return nil, err
	}
	return &imp{
		Binaries: binaries,
		master:   master,
	}, nil
}

type Imp interface {
	io.Closer
	BinaryProvider
	Open(context.Context, Ref) (Session, error)
	GetMasterPublicKey() (crypto.PublicKey, error)
}

type imp struct {
	*Binaries
	master *protocol.Master

	sessionToPort map[session.Id]uint16
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
