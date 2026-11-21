package management

import (
	"context"

	"github.com/engity-com/bifroest/pkg/cli/model"
	managementclient "github.com/engity-com/bifroest/pkg/management/client"
	"github.com/engity-com/bifroest/pkg/management/wire"
)

func (target Target) Metrics(ctx context.Context, names []string) (model.MetricsSnapshot, error) {
	args := append([]string{"metrics", "show", "--"}, names...)
	command, err := target.startWireCommand(ctx, wire.WireCommand, args...)
	if err != nil {
		return model.MetricsSnapshot{}, err
	}
	defer command.close()
	snapshot, err := managementclient.ReadWireResult[model.MetricsSnapshot](ctx, command.response("remote metrics command failed"))
	if err != nil {
		return model.MetricsSnapshot{}, err
	}
	if err := snapshot.Validate(); err != nil {
		return model.MetricsSnapshot{}, err
	}
	return snapshot, nil
}
