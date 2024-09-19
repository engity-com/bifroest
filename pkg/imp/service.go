package imp

import (
	"context"
	"crypto"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/imp/protocol"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

type Service struct {
	Version         common.Version
	Addr            string
	MasterPublicKey crypto.PublicKey

	Logger log.Logger
}

func (this *Service) Serve(ctx context.Context) error {
	fail := func(err error) error {
		return err
	}

	instance, err := this.createInstance()
	if err != nil {
		return fail(err)
	}

	if err := instance.serve(ctx); err != nil && !bnet.IsClosedError(err) {
		return fail(err)
	}
	return nil
}

func (this *Service) createInstance() (*service, error) {
	result := service{
		Service: this,
	}

	result.imp.Addr = this.Addr
	result.imp.MasterPublicKey = this.MasterPublicKey
	result.imp.Logger = this.logger()

	return &result, nil
}

func (this *Service) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("service")
}

type service struct {
	*Service

	imp protocol.Imp
}

func (this *service) serve(ctx context.Context) error {
	fail := func(err error) error {
		return err
	}

	if err := this.imp.Serve(ctx); err != nil {
		return fail(err)
	}

	return nil
}
