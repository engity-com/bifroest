package sftp_server

import (
	"context"
	goos "os"

	cli "github.com/echocat/cli4g"

	. "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/sftp"
)

type opts struct {
	WorkingDirectory string `flag:"workingDir" description:"Directory to start in."`
}

func newOpts(context.Context) (opts, error) {
	return opts{
		WorkingDirectory(),
	}, nil
}

func Register(_ context.Context, c cli.ContainerRequirementSetters, usage Usage) {
	if !usage.IncludeService() {
		return
	}

	c.AddCommand(cli.NewCommand[opts]().
		WithName("sftp-server").
		WithDescription("Run the sftp server instance used by this instance.").
		WithCreateOptionsHandler(newOpts).
		WithVisible(false).
		WithHandler(handle),
	)
}

func handle(_ context.Context, o opts) error {
	s := sftp.Server{
		WorkingDir: o.WorkingDirectory,
	}

	if err := s.Run(&stdpipe{}); err != nil {
		return err
	}
	return nil
}

type stdpipe struct{}

func (this *stdpipe) Read(p []byte) (n int, err error) {
	return goos.Stdin.Read(p)
}

func (this *stdpipe) Write(p []byte) (n int, err error) {
	return goos.Stdout.Write(p)
}

func (this *stdpipe) Close() (rErr error) {
	if err := goos.Stdin.Close(); err != nil {
		rErr = err
	}
	if err := goos.Stdout.Close(); err != nil && rErr == nil {
		rErr = err //nolint:staticcheck
	}
	return nil
}
