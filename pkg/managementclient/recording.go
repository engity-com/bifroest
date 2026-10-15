package managementclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/kevinburke/ssh_config"

	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/recording"
)

func RecordingPrivateKey(target Target) (string, error) {
	path, err := sshConfigValue(target.Host, "X-RecordingPrivateKey")
	if err != nil || path == "" {
		return "", err
	}
	return expandHome(path)
}

func ExpectedRecordingProducerID(target Target) (string, error) {
	return sshConfigValue(target.Host, "X-ExpectedProducerId")
}

func sshConfigValue(host, key string) (string, error) {
	return ssh_config.GetStrict(host, key)
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
	client, release, err := connect(ctx, target)
	if err != nil {
		return transport.RecordingArtifactHeader{}, err
	}
	defer release()
	sess, err := client.NewSession()
	if err != nil {
		return transport.RecordingArtifactHeader{}, err
	}
	defer sess.Close()
	stream, err := sess.StdoutPipe()
	if err != nil {
		return transport.RecordingArtifactHeader{}, err
	}
	var stderr diagnosticOutput
	sess.Stderr = &stderr
	request, err := transport.EncodeWireRequest([]string{"recording", name.String(), id.String()})
	if err != nil {
		return transport.RecordingArtifactHeader{}, err
	}
	sess.Stdin = bytes.NewReader(request)
	if err := sess.Start(transport.WireRecordingCommand); err != nil {
		return transport.RecordingArtifactHeader{}, err
	}
	header, err := transport.ReadRecordingArtifact(stream, output, recording.DefaultMaximumNativeRecordingBytes)
	if err != nil {
		return transport.RecordingArtifactHeader{}, fmt.Errorf("cannot download signed recording: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if err := sess.Wait(); err != nil {
		return transport.RecordingArtifactHeader{}, fmt.Errorf("remote recording transfer failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if header.ID != id.String() {
		return transport.RecordingArtifactHeader{}, fmt.Errorf("remote recording does not match requested ID")
	}
	return header, nil
}
