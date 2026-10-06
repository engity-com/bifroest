package main

import (
	"context"
	"io"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/management"
)

func TestAuditAndAuditlogShareArtifactSubcommands(t *testing.T) {
	app := kingpin.New("bifroest", "test").Terminate(func(int) {})
	registerAuditArtifactCommands(app.Command("audit", "legacy"))
	parent, _ := management.RegisterAuditlogCommands(app, nil, nil, context.Background(), io.Discard, true)
	registerAuditArtifactCommands(parent)
	require.NotSame(t, remoteAuditVerifyOpts["audit"], remoteAuditVerifyOpts["auditlog"])
	for _, args := range [][]string{
		{"audit", "verify", "default"},
		{"auditlog", "verify", "default"},
		{"audit", "export", "default"},
		{"auditlog", "export", "default"},
		{"auditlog", "ls"},
	} {
		_, err := app.ParseContext(args)
		require.NoError(t, err, "%v", args)
	}
}
