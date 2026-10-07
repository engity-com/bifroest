package forever

import (
	"context"
	goos "os"
	"os/signal"
	"syscall"

	cli "github.com/echocat/cli4g"

	. "github.com/engity-com/bifroest/pkg/cli/common"
)

func Register(_ context.Context, c cli.ContainerRequirementSetters, usage Usage) {
	if !usage.IncludeService() {
		return
	}

	c.AddCommand(cli.NewSimpleCommand().
		WithName("forever").
		WithDescription("This is a supporting command which simply runs forever until it receives a interrupt signal.").
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
