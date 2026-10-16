package sftp_server

import (
	"context"
	"io"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/sftp"
)

type opts struct {
	WorkingDirectory string `flag:"workingDir" description:"Directory to start in."`
}

func newOpts(context.Context) (opts, error) {
	return opts{
		common.WorkingDirectory(),
	}, nil
}

func CreateCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[opts]("sftp-server", "Run the sftp server instance used by this instance.").
			WithProfiles(common.ProfileExecutable).
			WithCreateOptionsHandler(newOpts).
			WithVisible(false).
			WithHandler(handle),
	}
}

func handle(ctx context.Context, o opts) error {
	s := sftp.Server{
		WorkingDir: o.WorkingDirectory,
	}

	if err := s.Run(&stdpipe{input: cli.StdinOfContext(ctx), output: cli.StdoutOfContext(ctx)}); err != nil {
		return err
	}
	return nil
}

type stdpipe struct {
	input  io.Reader
	output io.Writer
}

func (this *stdpipe) Read(p []byte) (n int, err error) {
	if this.input == nil {
		return 0, io.ErrClosedPipe
	}
	return this.input.Read(p)
}

func (this *stdpipe) Write(p []byte) (n int, err error) {
	if this.output == nil {
		return 0, io.ErrClosedPipe
	}
	return this.output.Write(p)
}

func (*stdpipe) Close() error { return nil } // Invocation streams are borrowed.
