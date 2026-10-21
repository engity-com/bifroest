package export

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
)

type keyOutputOpts struct {
	Output string `flag:"output" default:"-" placeholder:"<path|->" description:"Client output file or - for stdout."`
	Force  bool   `flag:"force" description:"Replace an existing client output file."`
}

func exportRemote(ctx context.Context, opts keyOutputOpts, args ...string) error {
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	if err := target.EnsureOutputSafe(ctx, opts.Output, cli.StdoutOfContext(ctx)); err != nil {
		return err
	}
	raw, err := target.ExportKey(ctx, args...)
	if err != nil {
		return err
	}
	return common.WriteBootstrapOutput(ctx, opts.Output, raw, opts.Force)
}

func exportManagement(ctx context.Context, request model.KeyExportRequest) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Keys == nil {
		return fmt.Errorf("management key operations are unavailable")
	}
	raw, err := access.Keys.Export(ctx, request)
	if err != nil {
		return err
	}
	if access.WireFormat {
		raw, err = transport.EncodeWireResult(raw)
		if err != nil {
			return err
		}
	}
	return common.WriteBootstrapOutput(ctx, "-", raw, false)
}
