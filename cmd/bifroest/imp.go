package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/session"
)

var _ = registerCommand(func(app *kingpin.Application) {
	addr := fmt.Sprintf(":%d", imp.ServicePort)
	var encodecMasterPublicKey string
	var sessionId session.Id

	cmd := app.Command("imp", "Runs the imp service.").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doImp(encodecMasterPublicKey, sessionId, addr)
		})
	cmd.Flag("addr", "Address to bind to.").
		Default(addr).
		PlaceHolder("[<host>]:<port>").
		StringVar(&addr)
	cmd.Flag("masterPublicKey", "Public SSH key of the master service which is accessing this imp instance.").
		Envar(imp.EnvVarMasterPublicKey).
		PlaceHolder("<base64 std raw encoded ssh public key>").
		Required().
		StringVar(&encodecMasterPublicKey)
	cmd.Flag("sessionId", "Session ID of which this IMP is working for.").
		Envar(session.EnvName).
		PlaceHolder("<sessionId>").
		Required().
		SetValue(&sessionId)
})

func doImp(encodecMasterPublicKey string, sessionId session.Id, addr string) error {
	service := imp.Service{
		Version:   versionV,
		SessionId: sessionId,
		Addr:      addr,
	}

	if b, err := base64.RawStdEncoding.DecodeString(encodecMasterPublicKey); err != nil {
		return errors.System.Newf("cannot decode imp master's public key: %w", err)
	} else if service.MasterPublicKey, err = crypto.ParsePublicKeyBytes(b); err != nil {
		return errors.System.Newf("cannot decode imp master's public key: %w", err)
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	sigs := make(chan os.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.With("signal", sig).Info("received signal")
		cancelFunc()
	}()

	log.WithAll(common.VersionToMap(versionV)).
		Info("Engity's Bifröst imp running...")

	if err := service.Serve(ctx); err != nil {
		log.WithError(err).Error()
		os.Exit(1)
	}

	log.Info("bye!")
	return nil
}
