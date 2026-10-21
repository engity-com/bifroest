package management

import (
	"context"
	"fmt"
	"io"

	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/recording"
)

func RecordingPrivateKey(target Target) (string, error) {
	path, err := sshConfigValue(target, "X-RecordingPrivateKey")
	if err != nil || path == "" {
		return "", err
	}
	return expandHome(path)
}

func ExpectedRecordingProducerID(target Target) (string, error) {
	return sshConfigValue(target, "X-ExpectedProducerId")
}

func sshConfigValue(target Target, key string) (string, error) {
	value, err := target.sshSettings().GetStrict(target.Host, key)
	if err != nil {
		return "", target.configurationError(err)
	}
	return value, nil
}

func DownloadRecording(ctx context.Context, target Target, auditlogName string, recordingID string, output io.Writer) (transport.RecordingArtifactHeader, error) {
	name := configuration.AuditlogName(auditlogName)
	if err := name.Validate(); err != nil {
		return transport.RecordingArtifactHeader{}, err
	}
	var id recording.Id
	if err := id.UnmarshalText([]byte(recordingID)); err != nil {
		return transport.RecordingArtifactHeader{}, err
	}
	if err := target.EnsureOutputSafe(ctx, "-", output); err != nil {
		return transport.RecordingArtifactHeader{}, err
	}
	command, err := target.startWireCommand(ctx, transport.WireRecordingCommand, "recording", name.String(), id.String())
	if err != nil {
		return transport.RecordingArtifactHeader{}, err
	}
	defer command.close()
	header, err := transport.ReadRecordingArtifact(command.stdout, output, recording.DefaultMaximumNativeRecordingBytes)
	if err != nil {
		return transport.RecordingArtifactHeader{}, command.failure("cannot download signed recording", err)
	}
	if err := command.wait("remote recording transfer failed"); err != nil {
		return transport.RecordingArtifactHeader{}, err
	}
	if header.ID != id.String() {
		return transport.RecordingArtifactHeader{}, fmt.Errorf("remote recording does not match requested ID")
	}
	return header, nil
}
