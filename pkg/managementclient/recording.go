package managementclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/kevinburke/ssh_config"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
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

func DownloadRecording(ctx context.Context, target Target, auditlogName string, recordingID string, output io.Writer) (management.RecordingArtifactHeader, error) {
	name := configuration.AuditlogName(auditlogName)
	if err := name.Validate(); err != nil {
		return management.RecordingArtifactHeader{}, err
	}
	var id recording.Id
	if err := id.UnmarshalText([]byte(recordingID)); err != nil {
		return management.RecordingArtifactHeader{}, err
	}
	client, release, err := connect(ctx, target)
	if err != nil {
		return management.RecordingArtifactHeader{}, err
	}
	defer release()
	sess, err := client.NewSession()
	if err != nil {
		return management.RecordingArtifactHeader{}, err
	}
	defer sess.Close()
	stream, err := sess.StdoutPipe()
	if err != nil {
		return management.RecordingArtifactHeader{}, err
	}
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	request, err := management.EncodeWireRequest([]string{"recording", name.String(), id.String()})
	if err != nil {
		return management.RecordingArtifactHeader{}, err
	}
	sess.Stdin = bytes.NewReader(request)
	if err := sess.Start(management.WireRecordingCommand); err != nil {
		return management.RecordingArtifactHeader{}, err
	}
	header, err := management.ReadRecordingArtifact(stream, output, recording.DefaultMaximumNativeRecordingBytes)
	if err != nil {
		return management.RecordingArtifactHeader{}, fmt.Errorf("cannot download signed recording: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if err := sess.Wait(); err != nil {
		return management.RecordingArtifactHeader{}, fmt.Errorf("remote recording transfer failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if header.ID != id.String() {
		return management.RecordingArtifactHeader{}, fmt.Errorf("remote recording does not match requested ID")
	}
	return header, nil
}
