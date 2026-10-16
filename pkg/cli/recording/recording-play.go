package recording

import (
	"context"
	"errors"
	"fmt"
	"io"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

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
		cli.NewCommand[managementPlayOptions]("play", "Verify and play a session Recording in the terminal.").
			WithProfiles(common.ProfileManagement).
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
	parent.AddCommand(cli.NewCommand[playCommandOptions]("play", "Verify and play a session Recording in the terminal.").
		WithProfiles(common.ProfileExecutable).
		WithHandler(func(ctx context.Context, o playCommandOptions) error {
			if target, remote := common.RemoteTargetFromContext(ctx); remote {
				return runRemotePlay(ctx, target, o, cli.StdoutOfContext(ctx))
			}
			return doRecordingPlay(ctx, o, cli.StdoutOfContext(ctx))
		}))
}

func doRecordingPlay(ctx context.Context, opts playCommandOptions, output io.Writer) error {
	if output == nil {
		return fmt.Errorf("missing playback output")
	}
	if !opts.WithSensitive {
		return fmt.Errorf("recording playback requires --with-sensitive")
	}
	if opts.Speed <= 0 || opts.Speed > 100 {
		return fmt.Errorf("--speed must be greater than zero and at most 100")
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		export := opts.exportCommandOptions
		export.Output = "-"
		err := doRecordingExport(ctx, export, writer)
		_ = writer.CloseWithError(err)
		done <- err
	}()
	playErr := PlayAsciicast(ctx, reader, output, opts.Speed)
	_ = reader.CloseWithError(playErr)
	return errors.Join(playErr, <-done)
}
