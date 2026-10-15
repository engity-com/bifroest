package recording

import (
	"context"
	"errors"
	"fmt"
	"io"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

type recordingPlayOpts struct {
	recordingExportOpts
	speed float64
}

type playCommandOptions struct {
	exportCommandOptions
	Speed float64 `flag:"speed" default:"1" description:"Playback speed multiplier, up to 100."`
}

type managementPlayOptions struct {
	managementExportOptions
	Speed float64 `flag:"speed" default:"1" description:"Playback speed multiplier, up to 100."`
}

func registerManagementPlay(parent cli.ContainerRequirementSetters) {
	parent.AddCommand(
		cli.NewCommand[managementPlayOptions]().
			WithName("play").
			WithDescription("Verify and play a session Recording in the terminal.").
			WithHandler(handleManagementPlay),
	)
}

func handleManagementPlay(ctx context.Context, opts managementPlayOptions) error {
	if !opts.WithSensitive {
		return fmt.Errorf("recording play requires --with-sensitive")
	}
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Recording == nil {
		return fmt.Errorf("management recording repository is unavailable")
	}
	return access.Recording.Play(ctx, opts.Auditlog, opts.ID, opts.Speed, cli.StdoutOfContext(ctx))
}

func registerRecordingPlayCmd(parent cli.ContainerRequirementSetters) {
	parent.AddCommand(cli.NewCommand[playCommandOptions]().
		WithName("play").
		WithDescription("Verify and play a session Recording in the terminal.").
		WithHandler(func(ctx context.Context, o playCommandOptions) error {
			if target, remote := common.RemoteTargetFromContext(ctx); remote {
				return runRemotePlay(ctx, target, o, cli.StdoutOfContext(ctx))
			}
			return doRecordingPlay(ctx, &recordingPlayOpts{recordingExportOpts: recordingExportOpts{
				file: o.File, recordingId: o.RecordingID, withSensitive: o.WithSensitive,
				configuration: o.Configuration, expectedProducerId: o.ExpectedProducerID,
				allowUntrusted: o.AllowUntrusted, decryptionIdentityFiles: o.DecryptionIdentityFiles,
			}, speed: o.Speed}, cli.StdoutOfContext(ctx))
		}))
}

func doRecordingPlay(ctx context.Context, opts *recordingPlayOpts, output io.Writer) error {
	if opts == nil || output == nil {
		return fmt.Errorf("missing playback options or output")
	}
	if !opts.withSensitive {
		return fmt.Errorf("recording playback requires --with-sensitive")
	}
	if opts.speed <= 0 || opts.speed > 100 {
		return fmt.Errorf("--speed must be greater than zero and at most 100")
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		export := opts.recordingExportOpts
		export.output = "-"
		err := doRecordingExport(ctx, &export, writer)
		_ = writer.CloseWithError(err)
		done <- err
	}()
	playErr := PlayAsciicast(ctx, reader, output, opts.speed)
	_ = reader.CloseWithError(playErr)
	return errors.Join(playErr, <-done)
}
