package audit

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
)

type producerOptions struct {
	common.ExecutableConfigurationOpts
	format.Opts
	ConfiguredAuditlogOptions
}

func registerProducerID(parent cli.ContainerRequirementSetters) {
	parent.AddCommand(
		cli.NewCommand[producerOptions]("producer-id", "Print the signing producer ID of an audit log.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleProducerID),
		cli.NewCommand[producerOptions]("producer-id", "Print the signing producer ID of an audit log.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementProducerID),
	)
}

func handleManagementProducerID(ctx context.Context, o producerOptions) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.ProducerID == nil {
		return fmt.Errorf("management audit identity is unavailable")
	}
	id, err := access.ProducerID(o.Name)
	if err != nil {
		return err
	}
	return format.WriteProducerID(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, o.Format), id.String())
}

func handleProducerID(ctx context.Context, o producerOptions) error {
	conf, err := common.ResolveConfiguration(ctx, o)
	if err != nil {
		return err
	}
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		if conf != nil {
			return fmt.Errorf("--configuration cannot be combined with a remote target")
		}
		return target.Run(ctx, "audit", "producer-id", o.Name.String(), "--format="+string(o.Format))
	}
	configured, err := FindConfigured(conf, o.Name)
	if err != nil {
		return err
	}
	if !configured.Enabled && !configured.Recording.Enabled {
		return fmt.Errorf("auditlog %q and its Recording are disabled", configured.Name)
	}
	key, err := LoadAuditPrivateKey(configured.IdentityFile)
	if err != nil {
		return err
	}
	identity, err := audit.NewIdentity(key)
	if err != nil {
		return err
	}
	return format.WriteProducerID(cli.StdoutOfContext(ctx), o.Format, identity.ProducerId().String())
}
