package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/anmitsu/go-shlex"
	clibase "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	cliCommon "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/model"
	clirecording "github.com/engity-com/bifroest/pkg/cli/recording"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/recording"
)

func (this *Service) warnOnManagementAccess() {
	for _, flow := range this.Configuration.Flows {
		if management, ok := flow.Environment.V.(*configuration.EnvironmentManagement); ok {
			if management.IncludingCredentials {
				this.logger().With("flow", flow.Name).Warn("management environment exposes Flow credentials; enable includingCredentials only temporarily for debugging or migration, never in production")
			}
			if management.AllowArtifactTransfer {
				this.logger().With("flow", flow.Name).Warn("management environment permits download of original audit and Recording artifacts; restrict allowArtifactTransfer to trusted administrators")
			}
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

func (this *service) RunManagementCommand(task environment.Task, includingCredentials, allowArtifactTransfer bool) (exitCode int, resultErr error) {
	defer func() {
		if resultErr != nil {
			_, _ = fmt.Fprintln(task.SshSession().Stderr(), resultErr)
		}
	}()
	raw := task.SshSession().RawCommand()
	if raw == transport.WireCommand {
		args, err := transport.DecodeWireRequest(task.SshSession())
		if err != nil {
			return -1, err
		}
		return this.runManagementArgs(task, includingCredentials, allowArtifactTransfer, args, true)
	}
	if raw == transport.WireRecordingCommand {
		if !allowArtifactTransfer {
			return -1, fmt.Errorf("raw artifact downloads require allowArtifactTransfer in the management environment")
		}
		args, err := transport.DecodeWireRequest(task.SshSession())
		if err != nil {
			return -1, err
		}
		return this.streamManagementRecording(task, args)
	}
	if raw == transport.WireAuditCommand {
		if !allowArtifactTransfer {
			return -1, fmt.Errorf("raw artifact downloads require allowArtifactTransfer in the management environment")
		}
		args, err := transport.DecodeWireRequest(task.SshSession())
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
	return this.runManagementArgs(task, includingCredentials, allowArtifactTransfer, args, false)
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
		snapshot, err := transport.SnapshotAudit(task.Context(), audit.JournalSource{
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
	if err := transport.WriteRecordingArtifact(task.SshSession(), transport.RecordingArtifactHeader{
		Version: 1, ID: id.String(), ProducerID: artifact.ProducerId().String(), Size: artifact.Size(), SHA256: artifact.ArtifactDigest().String(),
	}, artifact.Reader()); err != nil {
		return -1, err
	}
	return 0, nil
}

func (this *service) runManagementArgs(task environment.Task, includingCredentials, allowArtifactTransfer bool, args []string, wire bool) (int, error) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "@") {
			return -1, fmt.Errorf("management commands do not permit @file argument expansion")
		}
	}
	access := cliCommon.ManagementAccess{
		Configuration: &this.Configuration, Sessions: this.sessions,
		IncludingCredentials: includingCredentials, AllowArtifactTransfer: allowArtifactTransfer, WireFormat: wire,
		Audit:      managementAuditOperations{service: this, allowArtifactTransfer: allowArtifactTransfer},
		Recording:  managementRecordingOperations{service: this, allowArtifactTransfer: allowArtifactTransfer},
		Recordings: managementRecordingBrowser{service: this},
		ProducerID: func(name configuration.AuditlogName) (audit.ProducerId, error) {
			identity := this.auditIdentities[name]
			if identity == nil {
				return audit.ProducerId{}, fmt.Errorf("auditlog %q has no active signing identity", name)
			}
			return identity.ProducerId(), nil
		},
	}
	ctx := clibase.ContextWithStdio(task.Context(), task.SshSession(), task.SshSession(), task.SshSession().Stderr())
	ctx = cliCommon.ContextWithManagementAccess(ctx, access)
	if err := this.managementApplication.ParseAndExecute(ctx, &clibase.ParseOpts{
		Profiles: []string{cliCommon.ProfileManagement},
	}, args...); err != nil {
		return 1, err
	}
	return 0, nil
}

type managementRecordingBrowser struct{ service *service }

func (this managementRecordingBrowser) List(ctx context.Context, name configuration.AuditlogName) ([]model.RecordingView, error) {
	repository := this.service.recordingRepositories[name]
	if repository == nil || repository.native == nil {
		return nil, fmt.Errorf("auditlog %q has no active recording repository", name)
	}
	ids, err := repository.native.ListSealed(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]model.RecordingView, 0, len(ids))
	for _, id := range ids {
		artifact, err := repository.native.OpenSealed(ctx, id)
		if err != nil {
			return nil, err
		}
		view, err := clirecording.InspectRecording(ctx, name, artifact, artifact.Size(), repository.producerId)
		if closeErr := artifact.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, view)
	}
	return entries, nil
}

func (this managementRecordingBrowser) Detail(ctx context.Context, name configuration.AuditlogName, id recording.Id) (result model.RecordingView, resultErr error) {
	artifact, err := this.service.openManagementRecording(ctx, name.String(), id.String())
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, artifact.Close()) }()
	return clirecording.InspectRecording(ctx, name, artifact, artifact.Size(), artifact.ProducerId())
}
