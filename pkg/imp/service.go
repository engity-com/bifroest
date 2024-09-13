package imp

import (
	"context"
	"net"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/imp/protocol"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

type Service struct {
	Version common.Version

	ExpectedToken []byte

	Logger log.Logger
}

func (this *Service) Serve(ctx context.Context, ln net.Listener) error {
	fail := func(err error) error {
		return err
	}

	instance, err := this.createInstance()
	if err != nil {
		return fail(err)
	}

	if err := instance.serve(ctx, ln); err != nil && !bnet.IsClosedError(err) {
		return fail(err)
	}
	return nil
}

func (this *Service) createInstance() (*service, error) {
	result := service{
		Service: this,
	}

	result.server.Version = this.Version
	result.server.ExpectedToken = this.ExpectedToken
	result.server.Logger = this.logger()

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

	server protocol.Server
}

func (this *service) serve(ctx context.Context, ln net.Listener) error {
	fail := func(err error) error {
		return err
	}

	if err := this.server.Serve(ctx, ln); err != nil {
		return fail(err)
	}

	return nil
}
