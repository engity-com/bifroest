package management

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/engity-com/bifroest/pkg/cli/transport"
)

func (target Target) ExportKey(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) < 3 || args[0] != "key" || args[1] != "export" || args[2] != "public" && args[2] != "ca" && args[2] != "host" {
		return nil, fmt.Errorf("only public key exports are supported")
	}
	encoded, err := transport.EncodeWireRequest(args)
	if err != nil {
		return nil, err
	}
	client, release, err := connect(ctx, target)
	if err != nil {
		return nil, err
	}
	defer release()
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()
	session.Stdin = bytes.NewReader(encoded)
	var stderr diagnosticOutput
	session.Stderr = &stderr
	stream, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := session.Start(transport.WireCommand); err != nil {
		return nil, err
	}
	content, err := io.ReadAll(io.LimitReader(stream, transport.MaxWireResultBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > transport.MaxWireResultBytes {
		return nil, fmt.Errorf("key response exceeds %d bytes", transport.MaxWireResultBytes)
	}
	if err := session.Wait(); err != nil {
		return nil, fmt.Errorf("remote key command failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var result []byte
	if err := transport.DecodeWireResult(bytes.NewReader(content), &result); err != nil {
		return nil, err
	}
	return result, nil
}
