package management

import (
	"context"
	"fmt"

	managementclient "github.com/engity-com/bifroest/pkg/management/client"
	transport "github.com/engity-com/bifroest/pkg/management/wire"
)

func (target Target) ExportKey(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) < 3 || args[0] != "key" || args[1] != "export" || args[2] != "public" && args[2] != "ca" && args[2] != "host" {
		return nil, fmt.Errorf("only public key exports are supported")
	}
	command, err := target.startWireCommand(ctx, transport.WireCommand, args...)
	if err != nil {
		return nil, err
	}
	defer command.close()
	return managementclient.ReadWireResult[[]byte](ctx, command.response("remote key command failed"))
}
