package service

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/alecthomas/kingpin/v2"
	"github.com/anmitsu/go-shlex"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management"
)

type managementTermination struct{ status int }

func (this *service) RunManagementCommand(task environment.Task, includingCredentials bool) (exitCode int, resultErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if termination, ok := recovered.(managementTermination); ok {
				exitCode = termination.status
				resultErr = nil
			} else {
				panic(recovered)
			}
		}
	}()
	raw := task.SshSession().RawCommand()
	if len(raw) > 16<<10 || !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
		return -1, fmt.Errorf("invalid management command")
	}
	args, err := shlex.Split(raw, true)
	if err != nil {
		return -1, fmt.Errorf("invalid management command: %w", err)
	}
	app := kingpin.New("bifroest", "Inspect Bifröst over SSH.").Terminate(func(status int) { panic(managementTermination{status}) })
	app.UsageWriter(task.SshSession().Stderr()).ErrorWriter(task.SshSession().Stderr())
	management.RegisterFlowCommands(app, func(path string) (*configuration.Configuration, error) {
		if path != "" {
			return nil, fmt.Errorf("remote management commands do not accept local configuration files")
		}
		return &this.Configuration, nil
	}, task.SshSession(), includingCredentials, false)
	if _, err := app.Parse(args); err != nil {
		_, _ = fmt.Fprintln(task.SshSession().Stderr(), err)
		return 1, nil
	}
	return 0, nil
}
