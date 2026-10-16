package forever

import (
	"context"
	goos "os"
	"os/signal"
	"syscall"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func Register(c cli.ContainerRequirementSetters) {
	c.AddCommand(cli.NewSimpleCommand("forever", "This is a supporting command which simply runs forever until it receives a interrupt signal.").
		WithProfiles(common.ProfileExecutable).
		WithHandler(handle),
	)
}

func handle(context.Context, cli.NoOptions) error {
	sigs := make(chan goos.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	return nil
}
