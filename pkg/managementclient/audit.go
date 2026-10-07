package managementclient

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
)

func AuditPrivateKey(target Target) (string, error) {
	path, err := sshConfigValue(target.Host, "X-AuditPrivateKey")
	if err != nil || path == "" {
		return "", err
	}
	return expandHome(path)
}

func DownloadAuditSnapshot(ctx context.Context, target Target, auditlogName, root string) (management.AuditSnapshotHeader, error) {
	name := configuration.AuditlogName(auditlogName)
	if err := name.Validate(); err != nil {
		return management.AuditSnapshotHeader{}, err
	}
	client, release, err := connect(ctx, target)
	if err != nil {
		return management.AuditSnapshotHeader{}, err
	}
	defer release()
	sess, err := client.NewSession()
	if err != nil {
		return management.AuditSnapshotHeader{}, err
	}
	defer sess.Close()
	stream, err := sess.StdoutPipe()
	if err != nil {
		return management.AuditSnapshotHeader{}, err
	}
	var stderr diagnosticOutput
	sess.Stderr = &stderr
	request, err := management.EncodeWireRequest([]string{"auditlog", name.String()})
	if err != nil {
		return management.AuditSnapshotHeader{}, err
	}
	sess.Stdin = bytes.NewReader(request)
	if err := sess.Start(management.WireAuditCommand); err != nil {
		return management.AuditSnapshotHeader{}, err
	}
	header, err := management.ReadAuditSnapshot(stream, root)
	if err != nil {
		return management.AuditSnapshotHeader{}, fmt.Errorf("cannot download audit snapshot: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if err := sess.Wait(); err != nil {
		return management.AuditSnapshotHeader{}, fmt.Errorf("remote audit snapshot transfer failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if header.Name != name.String() {
		return management.AuditSnapshotHeader{}, fmt.Errorf("remote audit snapshot has the wrong auditlog name")
	}
	return header, nil
}
