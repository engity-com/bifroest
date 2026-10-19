package management

import (
	"bytes"
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/cli/transport"
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
	content, err := command.readResponse(transport.MaxWireResultBytes, "key response", "remote key command failed")
	if err != nil {
		return nil, err
	}
	var result []byte
	if err := transport.DecodeWireResult(bytes.NewReader(content), &result); err != nil {
		return nil, err
	}
	return result, nil
}
