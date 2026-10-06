package service

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management"
	"github.com/engity-com/bifroest/pkg/recording"
)

func (this *service) openManagementRecording(ctx context.Context, auditlogName string, recordingID string) (*recording.LocalSealedArtifact[recording.NativeRecordingSummary], error) {
	name := configuration.AuditlogName(auditlogName)
	if err := name.Validate(); err != nil {
		return nil, err
	}
	var id recording.Id
	if err := id.UnmarshalText([]byte(recordingID)); err != nil {
		return nil, err
	}
	repository := this.recordingRepositories[name]
	if repository == nil || repository.native == nil {
		return nil, fmt.Errorf("auditlog %q has no active recording repository", name)
	}
	return repository.native.OpenSealed(ctx, id)
}

func (this *service) registerManagementRecordingCommands(parent *kingpin.CmdClause, task environment.Task) {
	var verifyName, verifyID string
	var requireFull bool
	var verifyFormat string
	verify := management.RecordingArtifactCommand(parent, "verify")
	management.RequireFullVerificationFlag(verify, &requireFull)
	management.VerificationFormatFlag(verify, &verifyFormat)
	verify.Arg("auditlog", "Configured auditlog name.").Required().StringVar(&verifyName)
	verify.Arg("recordingId", "Recording UUID.").Required().StringVar(&verifyID)
	verify.Action(func(*kingpin.ParseContext) error {
		artifact, err := this.openManagementRecording(task.Context(), verifyName, verifyID)
		if err != nil {
			return err
		}
		defer artifact.Close()
		view, err := management.InspectRecording(task.Context(), configuration.AuditlogName(verifyName), artifact, artifact.Size(), artifact.ProducerId())
		if err != nil {
			return err
		}
		if requireFull && view.VerificationScope != "full" {
			return fmt.Errorf("full verification of encrypted Recordings requires a local private key; use bifroest @host recording verify")
		}
		return management.WriteVerification(task.SshSession(), management.Format(verifyFormat), view.VerificationScope)
	})
	registerSensitive := func(verb string, handler func(*recording.LocalSealedArtifact[recording.NativeRecordingSummary], float64) error) {
		var name, id string
		var withSensitive bool
		speed := float64(1)
		cmd := management.RecordingArtifactCommand(parent, verb)
		management.RecordingSensitiveFlag(cmd, &withSensitive)
		if verb == "play" {
			cmd.Flag("speed", "Playback speed multiplier (positive, at most 100).").Default("1").Float64Var(&speed)
		}
		cmd.Arg("auditlog", "Configured auditlog name.").Required().StringVar(&name)
		cmd.Arg("recordingId", "Recording UUID.").Required().StringVar(&id)
		cmd.Action(func(*kingpin.ParseContext) error {
			if !withSensitive {
				return fmt.Errorf("recording %s requires --with-sensitive", verb)
			}
			artifact, err := this.openManagementRecording(task.Context(), name, id)
			if err != nil {
				return err
			}
			defer artifact.Close()
			if artifact.Summary().RecipientFingerprint != "" {
				return fmt.Errorf("encrypted Recordings require a local private key; use bifroest @host recording %s", verb)
			}
			return handler(artifact, speed)
		})
	}
	exportCast := func(artifact *recording.LocalSealedArtifact[recording.NativeRecordingSummary], output io.Writer) error {
		_, err := recording.ExportNativeRecordingCast(artifact, artifact.Size(), nil, output, recording.NativeRecordingVerifyOptions{
			Context: task.Context(), ExpectedProducerId: artifact.ProducerId(),
		})
		return err
	}
	registerSensitive("export", func(artifact *recording.LocalSealedArtifact[recording.NativeRecordingSummary], _ float64) error {
		return exportCast(artifact, task.SshSession())
	})
	registerSensitive("play", func(artifact *recording.LocalSealedArtifact[recording.NativeRecordingSummary], speed float64) error {
		reader, writer := io.Pipe()
		result := make(chan error, 1)
		go func() {
			err := exportCast(artifact, writer)
			_ = writer.CloseWithError(err)
			result <- err
		}()
		playErr := management.PlayAsciicast(task.Context(), reader, task.SshSession(), speed)
		_ = reader.CloseWithError(playErr)
		return errors.Join(playErr, <-result)
	})
}
