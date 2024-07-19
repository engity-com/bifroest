package main

import (
	"github.com/alecthomas/kingpin"
	"github.com/engity-com/bifroest/pkg/sftp"
	"os"
)

func registerSftpServerCmd(app *kingpin.Application) {
	cmd := app.Command("sftp-server", "Run the sftp server instance used by this instance.").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doSftpServer()
		})
	cmd.Flag("workingDir", "Directory to start in.").
		Default(workingDir).
		StringVar(&workingDir)
}

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
	return os.Stdin.Read(p)
}

func (this *stdpipe) Write(p []byte) (n int, err error) {
	return os.Stdout.Write(p)
}

func (this *stdpipe) Close() (rErr error) {
	if err := os.Stdin.Close(); err != nil {
		rErr = err
	}
	if err := os.Stdout.Close(); err != nil && rErr == nil {
		rErr = err
	}
	return nil
}
