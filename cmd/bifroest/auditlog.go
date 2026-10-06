package main

import (
	"context"
	"fmt"
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
)

var remoteAuditEventsOpts *management.AuditEventsOptions

var _ = registerCommand(func(app *kingpin.Application) {
	parent, options := management.RegisterAuditlogCommands(app, loadManagementConfiguration, func(ctx context.Context, path string, name configuration.AuditlogName, sensitive bool, identities []string) ([]audit.VerifiedRecord, error) {
		conf, err := loadManagementConfiguration(path)
		if err != nil {
			return nil, err
		}
		for _, configured := range conf.Auditlogs {
			if configured.Name == name {
				key, err := loadAuditPrivateKey(configured.IdentityFile)
				if err != nil {
					return nil, err
				}
				identity, err := audit.NewIdentity(key)
				if err != nil {
					return nil, err
				}
				return management.ReadAuditEvents(ctx, conf, name, identity.ProducerId(), sensitive, identities)
			}
		}
		return nil, fmt.Errorf("auditlog %q does not exist", name)
	}, context.Background(), goos.Stdout, true)
	remoteAuditEventsOpts = options
	registerAuditArtifactCommands(parent)
})
