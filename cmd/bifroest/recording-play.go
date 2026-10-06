package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	goos "os"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
)

type recordingPlayOpts struct {
	recordingExportOpts
	speed float64
}

func registerRecordingPlayCmd(parent *kingpin.CmdClause) {
	opts := recordingPlayOpts{speed: 1, recordingExportOpts: recordingExportOpts{output: "-"}}
	cmd := parent.Command("play", "Verify and play a signed session Recording in the terminal.").
		Action(func(*kingpin.ParseContext) error { return doRecordingPlay(context.Background(), &opts, goos.Stdout) })
	cmd.Flag("with-sensitive", "Allow replay of potentially sensitive terminal output.").BoolVar(&opts.withSensitive)
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
	playErr := playAsciicast(ctx, reader, output, opts.speed)
	_ = reader.CloseWithError(playErr)
	return errors.Join(playErr, <-done)
}

func playAsciicast(ctx context.Context, source io.Reader, output io.Writer, speed float64) error {
	scanner := bufio.NewScanner(source)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return err
		}
		return fmt.Errorf("recording is empty")
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(scanner.Bytes(), &header); err != nil {
		return fmt.Errorf("invalid asciicast header: %w", err)
	}
	if header.Version != 3 {
		return fmt.Errorf("unsupported asciicast version %d", header.Version)
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		var event []json.RawMessage
		if err := json.Unmarshal([]byte(line), &event); err != nil || len(event) != 3 {
			return fmt.Errorf("invalid asciicast event: %v", err)
		}
		var elapsed float64
		var kind, value string
		if err := json.Unmarshal(event[0], &elapsed); err != nil || elapsed < 0 || elapsed > 365*24*60*60 {
			return fmt.Errorf("invalid asciicast event time")
		}
		if err := json.Unmarshal(event[1], &kind); err != nil {
			return err
		}
		if err := json.Unmarshal(event[2], &value); err != nil {
			return err
		}
		if delay := time.Duration(elapsed / speed * float64(time.Second)); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}
		if kind == "o" {
			if _, err := io.WriteString(output, value); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}
