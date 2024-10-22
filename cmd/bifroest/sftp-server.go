package main

import (
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/sftp"
)

var (
	workingDir = func() string {
		v, err := goos.Getwd()
		if err == nil {
			return v
		}
		return "/"
	}()
)

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("sftp-server", "Run the sftp server instance used by this instance.").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doSftpServer()
		})
	cmd.Flag("workingDir", "Directory to start in. Default: "+workingDir).
		PlaceHolder("<path>").
		StringVar(&workingDir)
})

func doSftpServer() error {
	s := sftp.Server{
		WorkingDir: workingDir,
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
		rErr = err //nolint:golint,staticcheck
	}
	return nil
}
