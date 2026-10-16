package recording

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/engity-com/bifroest/pkg/management"
)

// downloadRemoteRecording never sends a local decryption identity or output
// path to the server. The caller verifies the downloaded sealed artifact with
// a locally trusted producer before exposing its content.
type downloadedRecording struct {
	path     string
	producer string
	cleanup  func() error
}

func remoteRecordingIdentities(target management.Target, configured []string) ([]string, error) {
	if len(configured) != 0 {
		return configured, nil
	}
	path, err := management.RecordingPrivateKey(target)
	if err != nil || path == "" {
		return nil, err
	}
	return []string{path}, nil
}

func runRemoteVerify(ctx context.Context, target management.Target, options verifyCommandOptions, output io.Writer) (resultErr error) {
	if options.Configuration != "" {
		return fmt.Errorf("remote Recording commands cannot use --configuration")
	}
	downloaded, err := downloadRemoteRecording(ctx, target, options.File, options.RecordingID, options.ExpectedProducerID, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, downloaded.cleanup()) }()
	identities, err := remoteRecordingIdentities(target, options.DecryptionIdentityFiles)
	if err != nil {
		return err
	}
	options.File, options.RecordingID = downloaded.path, ""
	options.ExpectedProducerID, options.DecryptionIdentityFiles = downloaded.producer, identities
	return doRecordingVerify(ctx, options, output)
}

func runRemoteExport(ctx context.Context, target management.Target, options exportCommandOptions, output io.Writer) (resultErr error) {
	if !options.WithSensitive {
		return fmt.Errorf("recording export requires --with-sensitive")
	}
	if options.Configuration != "" {
		return fmt.Errorf("remote Recording commands cannot use --configuration")
	}
	downloaded, err := downloadRemoteRecording(ctx, target, options.File, options.RecordingID, options.ExpectedProducerID, options.AllowUntrusted)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, downloaded.cleanup()) }()
	identities, err := remoteRecordingIdentities(target, options.DecryptionIdentityFiles)
	if err != nil {
		return err
	}
	options.File, options.RecordingID = downloaded.path, ""
	options.ExpectedProducerID, options.DecryptionIdentityFiles = downloaded.producer, identities
	return doRecordingExport(ctx, options, output)
}

func runRemotePlay(ctx context.Context, target management.Target, options playCommandOptions, output io.Writer) (resultErr error) {
	if !options.WithSensitive {
		return fmt.Errorf("recording playback requires --with-sensitive")
	}
	if options.Configuration != "" {
		return fmt.Errorf("remote Recording commands cannot use --configuration")
	}
	downloaded, err := downloadRemoteRecording(ctx, target, options.File, options.RecordingID, options.ExpectedProducerID, options.AllowUntrusted)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, downloaded.cleanup()) }()
	identities, err := remoteRecordingIdentities(target, options.DecryptionIdentityFiles)
	if err != nil {
		return err
	}
	options.File, options.RecordingID = downloaded.path, ""
	options.ExpectedProducerID, options.DecryptionIdentityFiles = downloaded.producer, identities
	options.Output = "-"
	return doRecordingPlay(ctx, options, output)
}

func downloadRemoteRecording(ctx context.Context, target management.Target, auditlog, id, expected string, allowUntrusted bool) (downloadedRecording, error) {
	if auditlog == "" || id == "" {
		return downloadedRecording{}, fmt.Errorf("remote Recording commands require an auditlog name and Recording ID")
	}
	var err error
	if expected == "" {
		expected, err = management.ExpectedRecordingProducerID(target)
		if err != nil {
			return downloadedRecording{}, err
		}
	}
	if expected == "" && !allowUntrusted {
		return downloadedRecording{}, fmt.Errorf("remote Recording verification requires an independently trusted --expectedProducerId or X-ExpectedProducerId in the SSH config")
	}
	file, err := os.CreateTemp("", "bifroest-remote-recording-*")
	if err != nil {
		return downloadedRecording{}, err
	}
	remove := func() error {
		return errors.Join(file.Close(), os.Remove(file.Name()))
	}
	header, err := management.DownloadRecording(ctx, target, auditlog, id, file)
	if err == nil && expected != "" && header.ProducerID != expected {
		err = fmt.Errorf("remote Recording producer does not match the trusted ID")
	}
	if err == nil {
		err = file.Close()
	}
	if err != nil {
		return downloadedRecording{}, errors.Join(err, remove())
	}
	return downloadedRecording{path: file.Name(), producer: expected, cleanup: func() error {
		err := os.Remove(file.Name())
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}}, nil
}
