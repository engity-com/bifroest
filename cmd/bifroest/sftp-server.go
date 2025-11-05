package main

import (
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/sftp"
)

var _ = registerCommand(func(app *kingpin.Application) {
	cwd := workingDirectory()

	cmd := app.Command("sftp-server", "Run the sftp server instance used by this instance.").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doSftpServer(cwd)
		})
	cmd.Flag("workingDir", "Directory to start in.").
		Default(cwd).
		PlaceHolder("<path>").
		StringVar(&cwd)
})

func doSftpServer(cwd string) error {
	s := sftp.Server{
		WorkingDir: cwd,
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
