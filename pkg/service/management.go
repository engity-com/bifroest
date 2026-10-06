package service

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/alecthomas/kingpin/v2"
	"github.com/anmitsu/go-shlex"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management"
)

func (this *service) isManagementFlow(name configuration.FlowName) bool {
	for _, flow := range this.Configuration.Flows {
		if flow.Name == name {
			_, ok := flow.Environment.V.(*configuration.EnvironmentManagement)
			return ok
		}
	}
	return false
}

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
	if raw == management.WireCommand {
		args, err := management.DecodeWireRequest(task.SshSession())
		if err != nil {
			return -1, err
		}
		return this.runManagementArgs(task, includingCredentials, append(args, "--format=cbor"))
	}
	if len(raw) > 16<<10 || !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
		return -1, fmt.Errorf("invalid management command")
	}
	args, err := shlex.Split(raw, true)
	if err != nil {
		return -1, fmt.Errorf("invalid management command: %w", err)
	}
	return this.runManagementArgs(task, includingCredentials, args)
}

func (this *service) runManagementArgs(task environment.Task, includingCredentials bool, args []string) (int, error) {
	app := kingpin.New("bifroest", "Inspect Bifröst over SSH.").Terminate(func(status int) { panic(managementTermination{status}) })
	app.UsageWriter(task.SshSession().Stderr()).ErrorWriter(task.SshSession().Stderr())
	management.RegisterFlowCommands(app, func(path string) (*configuration.Configuration, error) {
		if path != "" {
			return nil, fmt.Errorf("remote management commands do not accept local configuration files")
		}
		return &this.Configuration, nil
	}, task.SshSession(), includingCredentials, false)
	management.RegisterSessionCommands(app, management.SessionSourceFromRepository(this.sessions), task.Context(), task.SshSession(), task.SshSession().Stderr(), false)
	management.RegisterAuditlogCommands(app, func(path string) (*configuration.Configuration, error) {
		if path != "" {
			return nil, fmt.Errorf("remote management commands do not accept local configuration files")
		}
		return &this.Configuration, nil
	}, func(ctx context.Context, path string, name configuration.AuditlogName, sensitive bool, identities []string) ([]audit.VerifiedRecord, error) {
		if path != "" || len(identities) != 0 {
			return nil, fmt.Errorf("remote management commands cannot read local files")
		}
		identity := this.auditIdentities[name]
		if identity == nil {
			return nil, fmt.Errorf("auditlog %q has no active signing identity", name)
		}
		return management.ReadAuditEvents(ctx, &this.Configuration, name, identity.ProducerId(), sensitive, nil)
	}, task.Context(), task.SshSession(), false)
	management.RegisterRecordingCommands(app.Command("recording", "Inspect sealed session recordings."), func(ctx context.Context, path string, name configuration.AuditlogName) ([]management.RecordingView, error) {
		if path != "" {
			return nil, fmt.Errorf("remote recording commands cannot read local configuration files")
		}
		repository := this.recordingRepositories[name]
		if repository == nil || repository.native == nil {
			return nil, fmt.Errorf("auditlog %q has no active recording repository", name)
		}
		ids, err := repository.native.ListSealed(ctx)
		if err != nil {
			return nil, err
		}
		entries := make([]management.RecordingView, 0, len(ids))
		for _, id := range ids {
			artifact, err := repository.native.OpenSealed(ctx, id)
			if err != nil {
				return nil, err
			}
			view, err := management.InspectRecording(ctx, name, artifact, artifact.Size(), repository.producerId)
			if closeErr := artifact.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				return nil, err
			}
			entries = append(entries, view)
		}
		return entries, nil
	}, task.Context(), task.SshSession(), false)
	if _, err := app.Parse(args); err != nil {
		_, _ = fmt.Fprintln(task.SshSession().Stderr(), err)
		return 1, nil
	}
	return 0, nil
}
