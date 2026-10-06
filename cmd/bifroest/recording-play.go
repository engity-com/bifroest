package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/management"
)

type recordingPlayOpts struct {
	recordingExportOpts
	speed float64
}

var remoteRecordingPlayOpts *recordingPlayOpts

func registerRecordingPlayCmd(parent *kingpin.CmdClause) {
	opts := recordingPlayOpts{speed: 1, recordingExportOpts: recordingExportOpts{output: "-"}}
	remoteRecordingPlayOpts = &opts
	cmd := management.RecordingArtifactCommand(parent, "play").
		Action(func(*kingpin.ParseContext) error { return doRecordingPlay(context.Background(), &opts, goos.Stdout) })
	management.RecordingSensitiveFlag(cmd, &opts.withSensitive)
	cmd.Flag("speed", "Playback speed multiplier (positive, default 1).").Default("1").Float64Var(&opts.speed)
	cmd.Flag("configuration", "Configuration for a local Recording (defaults to "+defaultConfigurationRef+").").Short('c').StringVar(&opts.configuration)
	cmd.Flag("expectedProducerId", "Trusted producer ID for an offline artifact.").StringVar(&opts.expectedProducerId)
	cmd.Flag("allowUntrusted", "Allow a self-signed, cryptographically valid Recording without a trusted producer.").BoolVar(&opts.allowUntrusted)
	cmd.Flag("decryptionIdentityFile", "Local private key for encrypted Recording; repeatable.").StringsVar(&opts.decryptionIdentityFiles)
	cmd.Arg("fileOrAuditlog", "Local Recording file or configured auditlog.").StringVar(&opts.file)
	cmd.Arg("recordingId", "Recording UUID when selecting an auditlog.").StringVar(&opts.recordingId)
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
		err := doRecordingExport(&export, writer)
		_ = writer.CloseWithError(err)
		done <- err
	}()
	playErr := management.PlayAsciicast(ctx, reader, output, opts.speed)
	_ = reader.CloseWithError(playErr)
	return errors.Join(playErr, <-done)
}
