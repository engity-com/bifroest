package management

import (
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func AuditPrivateKey(target Target) (string, error) {
	path, err := sshConfigValue(target.Host, "X-AuditPrivateKey")
	if err != nil || path == "" {
		return "", err
	}
	return expandHome(path)
}

func DownloadAuditSnapshot(ctx context.Context, target Target, auditlogName, root string) (transport.AuditSnapshotHeader, error) {
	name := configuration.AuditlogName(auditlogName)
	if err := name.Validate(); err != nil {
		return transport.AuditSnapshotHeader{}, err
	}
	cmd, err := target.startWireCommand(ctx, transport.WireAuditCommand, "auditlog", name.String())
	if err != nil {
		return transport.AuditSnapshotHeader{}, err
	}
	defer cmd.close()
	header, err := transport.ReadAuditSnapshot(cmd.stdout, root)
	if err != nil {
		return transport.AuditSnapshotHeader{}, cmd.failure("cannot download audit snapshot", err)
	}
	if err := cmd.wait("remote audit snapshot transfer failed"); err != nil {
		return transport.AuditSnapshotHeader{}, err
	}
	if header.Name != name.String() {
		return transport.AuditSnapshotHeader{}, fmt.Errorf("remote audit snapshot has the wrong auditlog name")
	}
	return header, nil
}
