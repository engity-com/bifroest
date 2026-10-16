package imp

import (
	"context"
	"encoding/base64"
	"fmt"
	goos "os"
	"os/signal"
	"syscall"

	cli "github.com/echocat/cli4g"
	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/internal/imp/protocol"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

type opts struct {
	Addr                       string     `flag:"addr" placeholder:"[<host>]:<port>" description:"Address to bind to."`
	MasterPublicKey            string     `flag:"masterPublicKey" env:"BIFROEST_MASTER_PUBLIC_KEY" required:"true" placeholder:"<base64 std raw encoded ssh public key>" description:"Public SSH key of the master service which is accessing this imp instance."`
	ExitCodeByConnectionIdPath string     `flag:"exitCodeByConnectionIdPath" placeholder:"<path>" description:"Contains exitCodes by their connectionId."`
	SessionId                  session.Id `flag:"sessionId" env:"BIFROEST_SESSION_ID" placeholder:"<sessionId>" description:"Session ID of which this IMP is working for."`
}

func newOpts(context.Context) (opts, error) {
	return opts{
		fmt.Sprintf(":%d", imp.ServicePort),
		"",
		protocol.DefaultExitCodeByConnectionIdPath,
		session.Id{},
	}, nil
}

func CreateCommands(version sys.Version) []cli.CommandRequirementLike {
	return append(createImpCommands(version), createInitCommands(version)...)
}

func createImpCommands(version sys.Version) []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[opts]("imp", "Runs the imp service.").
			WithProfiles(common.ProfileExecutable).
			WithVisible(false).
			WithCreateOptionsHandler(newOpts).
			WithHandler(func(ctx context.Context, o opts) error {
				return handler(ctx, o, version)
			}),
	}
}

func handler(ctx context.Context, o opts, version sys.Version) error {
	service := imp.Service{
		Version:                    version,
		SessionId:                  o.SessionId,
		ExitCodeByConnectionIdPath: o.ExitCodeByConnectionIdPath,
		Addr:                       o.Addr,
	}
	service.ReverseTCPUser, service.ReverseTCPUserConfigured = goos.LookupEnv(imp.EnvVarReverseTCPUser)

	if b, err := base64.RawStdEncoding.DecodeString(o.MasterPublicKey); err != nil {
		return errors.System.Newf("cannot decode imp master's public key: %w", err)
	} else if service.MasterPublicKey, err = crypto.ParsePublicKeyBytes(b); err != nil {
		return errors.System.Newf("cannot decode imp master's public key: %w", err)
	}

	ctx, cancelFunc := context.WithCancel(ctx)
	defer cancelFunc()

	sigs := make(chan goos.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		select {
		case sig := <-sigs:
			log.With("signal", sig).Info("received signal")
			cancelFunc()
		case <-ctx.Done():
		}
	}()

	log.WithAll(sys.VersionToMap(version)).
		Info("Engity's Bifröst imp running...")

	if err := service.Serve(ctx); err != nil {
		return err
	}

	log.Info("bye!")
	return nil
}
