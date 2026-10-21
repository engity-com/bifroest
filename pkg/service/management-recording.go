package service

import (
	"context"
	"errors"
	"fmt"
	"io"

	clirecording "github.com/engity-com/bifroest/pkg/cli/recording"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/recording"
)

type managementRecordingOperations struct {
	service               *service
	allowArtifactTransfer bool
}

func (this managementRecordingOperations) Verify(ctx context.Context, name configuration.AuditlogName, id recording.Id, requireFull bool) (scope string, resultErr error) {
	artifact, err := this.service.openManagementRecording(ctx, name.String(), id.String())
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, artifact.Close()) }()
	view, err := clirecording.InspectRecording(ctx, name, artifact, artifact.Size(), artifact.ProducerId())
	if err != nil {
		return "", err
	}
	if requireFull && view.VerificationScope != "full" {
		return "", fmt.Errorf("full verification of encrypted Recordings requires a local private key; use bifroest @host recording verify")
	}
	return view.VerificationScope, nil
}

func (this managementRecordingOperations) Export(ctx context.Context, name configuration.AuditlogName, id recording.Id, output io.Writer) (resultErr error) {
	if !this.allowArtifactTransfer {
		return fmt.Errorf("recording content requires allowArtifactTransfer in the management environment")
	}
	artifact, err := this.service.openManagementRecording(ctx, name.String(), id.String())
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, artifact.Close()) }()
	if artifact.Summary().RecipientFingerprint != "" {
		return fmt.Errorf("encrypted Recordings require a local private key; use bifroest @host recording export")
	}
	_, err = recording.ExportNativeRecordingCast(artifact, artifact.Size(), nil, output, recording.NativeRecordingVerifyOptions{
		Context: ctx, ExpectedProducerId: artifact.ProducerId(),
	})
	return err
}

func (this managementRecordingOperations) Play(ctx context.Context, name configuration.AuditlogName, id recording.Id, speed float64, output io.Writer) error {
	if !this.allowArtifactTransfer {
		return fmt.Errorf("recording content requires allowArtifactTransfer in the management environment")
	}
	reader, writer := io.Pipe()
	finished := make(chan error, 1)
	go func() {
		err := this.Export(ctx, name, id, writer)
		_ = writer.CloseWithError(err)
		finished <- err
	}()
	playErr := clirecording.PlayAsciicast(ctx, reader, output, speed)
	_ = reader.CloseWithError(playErr)
	return errors.Join(playErr, <-finished)
}

func (this *service) openManagementRecording(ctx context.Context, auditlogName, recordingID string) (*recording.LocalSealedArtifact[recording.NativeRecordingSummary], error) {
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
