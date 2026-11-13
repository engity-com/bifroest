package management

import (
	"context"

	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	managementclient "github.com/engity-com/bifroest/pkg/management/client"
)

func AuditPrivateKey(target Target) (string, error) {
	path, err := sshConfigValue(target, "X-AuditPrivateKey")
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
	return managementclient.ReadAuditSnapshot(ctx, cmd.response("remote audit snapshot transfer failed"), name.String(), transport.NewAuditSnapshotFileSink(root))
}
