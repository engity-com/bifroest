package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	goos "os"

	"github.com/engity-com/bifroest/pkg/managementclient"
)

func doRemoteRecordingCommand(ctx context.Context, target *managementTarget, command string, output io.Writer) (resultErr error) {
	if target == nil {
		return fmt.Errorf("a remote target is required")
	}
	var auditlog, id, expected, configurationPath string
	var identities []string
	allowUntrusted := false
	switch command {
	case "recording verify":
		if remoteRecordingVerifyOpts == nil {
			return fmt.Errorf("recording verification is not registered")
		}
		opts := remoteRecordingVerifyOpts
		auditlog, id, expected, configurationPath, identities = opts.file, opts.recordingId, opts.expectedProducerId, opts.configuration, opts.decryptionIdentityFiles
	case "recording export":
		if remoteRecordingExportOpts == nil {
			return fmt.Errorf("recording export is not registered")
		}
		opts := remoteRecordingExportOpts
		auditlog, id, expected, configurationPath, identities, allowUntrusted = opts.file, opts.recordingId, opts.expectedProducerId, opts.configuration, opts.decryptionIdentityFiles, opts.allowUntrusted
	case "recording play":
		if remoteRecordingPlayOpts == nil {
			return fmt.Errorf("recording playback is not registered")
		}
		opts := remoteRecordingPlayOpts
		auditlog, id, expected, configurationPath, identities, allowUntrusted = opts.file, opts.recordingId, opts.expectedProducerId, opts.configuration, opts.decryptionIdentityFiles, opts.allowUntrusted
	default:
		return fmt.Errorf("unsupported remote Recording command %q", command)
	}
	if configurationPath != "" || auditlog == "" || id == "" {
		return fmt.Errorf("remote Recording commands require an auditlog name and Recording ID, without --configuration or a local file path")
	}
	remote := managementclient.Target{Host: target.RawHost, User: target.User, Port: target.Port, ExplicitPort: target.ExplicitPort}
	if expected == "" {
		var err error
		expected, err = managementclient.ExpectedRecordingProducerID(remote)
		if err != nil {
			return err
		}
	}
	if expected == "" && !allowUntrusted {
		return fmt.Errorf("remote Recording verification requires an independently trusted --expectedProducerId or X-ExpectedProducerId in the SSH config")
	}
	if len(identities) == 0 {
		path, err := managementclient.RecordingPrivateKey(remote)
		if err != nil {
			return err
		}
		if path != "" {
			identities = []string{path}
		}
	}
	artifact, err := goos.CreateTemp("", "bifroest-remote-recording-*")
	if err != nil {
		return err
	}
	defer func() {
		if err := artifact.Close(); err != nil && !errors.Is(err, goos.ErrClosed) {
			resultErr = errors.Join(resultErr, err)
		}
		resultErr = errors.Join(resultErr, goos.Remove(artifact.Name()))
	}()
	header, err := managementclient.DownloadRecording(ctx, remote, auditlog, id, artifact)
	if err != nil {
		return err
	}
	if expected != "" && header.ProducerID != expected {
		return fmt.Errorf("remote Recording producer does not match the trusted ID")
	}
	if err := artifact.Close(); err != nil {
		return err
	}
	switch command {
	case "recording verify":
		opts := *remoteRecordingVerifyOpts
		opts.file, opts.recordingId, opts.configuration, opts.expectedProducerId, opts.decryptionIdentityFiles = artifact.Name(), "", "", expected, identities
		return doRecordingVerify(&opts, output)
	case "recording export":
		opts := *remoteRecordingExportOpts
		opts.file, opts.recordingId, opts.configuration, opts.expectedProducerId, opts.decryptionIdentityFiles = artifact.Name(), "", "", expected, identities
		return doRecordingExport(&opts, output)
	case "recording play":
		opts := *remoteRecordingPlayOpts
		opts.file, opts.recordingId, opts.configuration, opts.expectedProducerId, opts.decryptionIdentityFiles = artifact.Name(), "", "", expected, identities
		return doRecordingPlay(ctx, &opts, output)
	default:
		return fmt.Errorf("unsupported remote Recording command %q", command)
	}
}
