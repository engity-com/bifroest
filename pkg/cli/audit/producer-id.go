package audit

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/managementclient"
)

type producerOptions struct {
	configuration.EmptyStrOpts
	format.Opts
	Name configuration.AuditlogName `argument:"auditlogName" required:"true" description:"Configured auditlog whose signing identity to inspect."`
}

type managementProducerOptions struct {
	format.Opts
	Name configuration.AuditlogName `argument:"auditlogName" required:"true" description:"Configured auditlog whose signing identity to inspect."`
}

func registerProducerID(parent cli.ContainerRequirementSetters, usage common.Usage) {
	if usage == common.UsageManagement {
		parent.AddCommand(cli.NewCommand[managementProducerOptions]().
			WithName("producer-id").
			WithDescription("Print the signing producer ID of an audit log.").
			WithHandler(func(ctx context.Context, o managementProducerOptions) error {
				access, ok := common.ManagementAccessFromContext(ctx)
				if !ok || access.ProducerID == nil {
					return fmt.Errorf("management audit identity is unavailable")
				}
				id, err := access.ProducerID(o.Name)
				if err != nil {
					return err
				}
				return format.WriteProducerID(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, o.Format), id.String())
			}))
		return
	}
	parent.AddCommand(cli.NewCommand[producerOptions]().
		WithName("producer-id").
		WithDescription("Print the signing producer ID of an audit log.").
		WithHandler(func(ctx context.Context, o producerOptions) error {
			if target, remote := common.RemoteTargetFromContext(ctx); remote {
				if o.Configuration != "" {
					return fmt.Errorf("--configuration cannot be combined with a remote target")
				}
				return managementclient.Run(ctx, target,
					[]string{"audit", "producer-id", o.Name.String(), "--format=" + string(o.Format)}, cli.StdoutOfContext(ctx))
			}
			conf, err := common.LoadManagementConfiguration(o.Configuration)
			if err != nil {
				return err
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
		}))
}
