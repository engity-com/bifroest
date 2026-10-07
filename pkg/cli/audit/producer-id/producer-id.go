package producer_id

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	audit2 "github.com/engity-com/bifroest/pkg/cli/audit"
	. "github.com/engity-com/bifroest/pkg/cli/audit/common"
	. "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
)

type opts struct {
	configuration.Opts
	configuration.AuditlogNameOpts

	commandRoot string // Is this really required??
}

type optsWithFormat struct {
	opts
	format.Opts
}

var remoteAuditProducerIdOpts = map[string]*opts{}

func Register(_ context.Context, c cli.ContainerRequirementSetters, usage Usage) {
	o := opts{}
	o.commandRoot = cmds.FullCommand()
	remoteAuditProducerIdOpts[cmds.FullCommand()] = &o
	c.AddCommand(cli.NewCommand[opts]().
		WithName("producer-id").
		WithDescription("Print the signing producer ID of an audit log.").
		WithHandler(handle),
	)
}

func handle(ctx context.Context, o opts) error {
	return handleWithFormat(ctx, optsWithFormat{o, format.Opts{}})
}

func handleWithFormat(ctx context.Context, o optsWithFormat) error {
	configured, err := FindConfigured(&o.Configuration, o.Auditlog)
	if err != nil {
		return err
	}
	if !configured.Enabled && !configured.Recording.Enabled {
		return fmt.Errorf("auditlog %q and its Recording are disabled", configured.Name)
	}
	privateKey, err := LoadAuditPrivateKey(configured.IdentityFile)
	if err != nil {
		return fmt.Errorf("cannot load identity of auditlog %q: %w", configured.Name, err)
	}
	identity, err := audit.NewIdentity(privateKey)
	if err != nil {
		return fmt.Errorf("cannot use identity of auditlog %q: %w", configured.Name, err)
	}
	return management.WriteProducerID(cli.StdoutOfContext(ctx), audit2.selectedAuditFormat(o.commandRoot, o.Format), identity.ProducerId().String())
}
