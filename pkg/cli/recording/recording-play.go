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
	recordingContentOptions
	Speed float64 `flag:"speed" default:"1" description:"Playback speed multiplier, up to 100."`
}

type managementPlayOptions struct {
	managementExportOptions
	Speed float64 `flag:"speed" default:"1" description:"Playback speed multiplier, up to 100."`
}

func createPlayCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[managementPlayOptions]("play", "Verify and play a session Recording in the terminal.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementPlay),
		cli.NewCommand[playCommandOptions]("play", "Verify and play a session Recording in the terminal.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(func(ctx context.Context, o playCommandOptions) error {
				return doRecordingPlay(ctx, o, cli.StdoutOfContext(ctx))
			}),
		cli.NewCommand[playCommandOptions]("play", "Verify and play a session Recording in the terminal.").
			WithProfiles(common.ProfileRemote).
			WithHandler(remoteHandlePlay),
	}
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
	return withRecordingContent(ctx, opts.recordingContentOptions, func(content verifiedRecordingContent) error {
		if err := content.validateOutput("-", output); err != nil {
			return err
		}
		reader, writer := io.Pipe()
		done := make(chan error, 1)
		go func() {
			err := content.writeTo(writer)
			_ = writer.CloseWithError(err)
			done <- err
		}()
		playErr := PlayAsciicast(ctx, reader, output, opts.Speed)
		_ = reader.CloseWithError(playErr)
		return errors.Join(playErr, <-done, content.validateOutput("-", output))
	})
}
