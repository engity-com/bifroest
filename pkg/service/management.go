package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/alecthomas/kingpin/v2"
	"github.com/anmitsu/go-shlex"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management"
	"github.com/engity-com/bifroest/pkg/recording"
)

func (this *Service) warnOnManagementCredentials() {
	for _, flow := range this.Configuration.Flows {
		if management, ok := flow.Environment.V.(*configuration.EnvironmentManagement); ok && management.IncludingCredentials {
			this.logger().With("flow", flow.Name).Warn("management environment exposes Flow credentials; enable includingCredentials only temporarily for debugging or migration, never in production")
		}
	}
}

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
	defer func() {
		if resultErr != nil {
			_, _ = fmt.Fprintln(task.SshSession().Stderr(), resultErr)
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
	if raw == management.WireRecordingCommand {
		args, err := management.DecodeWireRequest(task.SshSession())
		if err != nil {
			return -1, err
		}
		return this.streamManagementRecording(task, args)
	}
	if raw == management.WireAuditCommand {
		args, err := management.DecodeWireRequest(task.SshSession())
		if err != nil {
			return -1, err
		}
		return this.streamManagementAudit(task, args)
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

func (this *service) streamManagementAudit(task environment.Task, args []string) (int, error) {
	if len(args) != 2 || args[0] != "auditlog" {
		return -1, fmt.Errorf("audit snapshot requires an auditlog name")
	}
	name := configuration.AuditlogName(args[1])
	if err := name.Validate(); err != nil {
		return -1, err
	}
	identity := this.auditIdentities[name]
	if identity == nil {
		return -1, fmt.Errorf("auditlog %q has no active signing identity", name)
	}
	for _, conf := range this.Configuration.Auditlogs {
		if conf.Name != name {
			continue
		}
		if !conf.Enabled {
			return -1, fmt.Errorf("auditlog %q is disabled", name)
		}
		key, err := audit.ResolveEncryptionPublicKey(conf.EncryptionPublicKey, conf.EncryptionPublicKeyFile)
		if err != nil {
			return -1, err
		}
		recipient, err := audit.EncryptionRecipientFingerprint(key)
		if err != nil {
			return -1, err
		}
		snapshot, err := management.SnapshotAudit(task.Context(), audit.JournalSource{
			Name: name.String(), Directory: conf.Directory, ExpectedProducerId: identity.ProducerId(), ExpectedEncryptionRecipient: recipient,
		})
		if err != nil {
			return -1, err
		}
		defer snapshot.Close()
		if err := snapshot.StreamTo(task.SshSession()); err != nil {
			return -1, err
		}
		return 0, nil
	}
	return -1, fmt.Errorf("auditlog %q does not exist", name)
}

func (this *service) streamManagementRecording(task environment.Task, args []string) (int, error) {
	if len(args) != 3 || args[0] != "recording" {
		return -1, fmt.Errorf("recording artifact requires an auditlog and Recording ID")
	}
	name := configuration.AuditlogName(args[1])
	if err := name.Validate(); err != nil {
		return -1, err
	}
	var id recording.Id
	if err := id.UnmarshalText([]byte(args[2])); err != nil {
		return -1, err
	}
	repository := this.recordingRepositories[name]
	if repository == nil || repository.native == nil {
		return -1, fmt.Errorf("auditlog %q has no active recording repository", name)
	}
	artifact, err := repository.native.OpenSealed(task.Context(), id)
	if err != nil {
		return -1, err
	}
	defer artifact.Close()
	if artifact.Size() > recording.DefaultMaximumNativeRecordingBytes {
		return -1, fmt.Errorf("recording exceeds the maximum supported artifact size")
	}
	if err := management.WriteRecordingArtifact(task.SshSession(), management.RecordingArtifactHeader{
		Version: 1, ID: id.String(), ProducerID: artifact.ProducerId().String(), Size: artifact.Size(), SHA256: artifact.ArtifactDigest().String(),
	}, artifact.Reader()); err != nil {
		return -1, err
	}
	return 0, nil
}

func (this *service) runManagementArgs(task environment.Task, includingCredentials bool, args []string) (int, error) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "@") {
			return -1, fmt.Errorf("management commands do not permit @file argument expansion")
		}
	}
	app := kingpin.New("bifroest", "Inspect Bifröst over SSH.").Terminate(func(status int) { panic(managementTermination{status}) })
	app.UsageWriter(task.SshSession().Stderr()).ErrorWriter(task.SshSession().Stderr())
	management.RegisterFlowCommands(app, func(path string) (*configuration.Configuration, error) {
		if path != "" {
			return nil, fmt.Errorf("remote management commands do not accept local configuration files")
		}
		return &this.Configuration, nil
	}, task.SshSession(), includingCredentials, false)
	management.RegisterSessionCommands(app, management.SessionSourceFromRepository(this.sessions), task.Context(), task.SshSession(), task.SshSession().Stderr(), false)
	auditlogCommands, auditOptions := management.RegisterAuditlogCommands(app, func(path string) (*configuration.Configuration, error) {
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
	this.registerManagementAuditCommands(auditlogCommands, task, &auditOptions.Format)
	this.registerManagementAuditCommands(app.Command("audit", "Inspect signed audit journals."), task, nil)
	recordingCommands := app.Command("recording", "Inspect sealed session recordings.")
	management.RegisterRecordingCommands(recordingCommands, func(ctx context.Context, path string, name configuration.AuditlogName) ([]management.RecordingView, error) {
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
	}, func(ctx context.Context, path string, name configuration.AuditlogName, id recording.Id) (result management.RecordingView, resultErr error) {
		if path != "" {
			return result, fmt.Errorf("remote recording commands cannot read local configuration files")
		}
		artifact, err := this.openManagementRecording(ctx, name.String(), id.String())
		if err != nil {
			return result, err
		}
		defer func() { resultErr = errors.Join(resultErr, artifact.Close()) }()
		return management.InspectRecording(ctx, name, artifact, artifact.Size(), artifact.ProducerId())
	}, task.Context(), task.SshSession(), false)
	this.registerManagementRecordingCommands(recordingCommands, task)
	if _, err := app.Parse(args); err != nil {
		_, _ = fmt.Fprintln(task.SshSession().Stderr(), err)
		return 1, nil
	}
	return 0, nil
}
