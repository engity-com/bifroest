package main

import (
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/management"
	"github.com/engity-com/bifroest/pkg/managementclient"
)

func TestSensitiveRemoteAuditEventsAcceptExplicitTrustedProducer(t *testing.T) {
	const expected = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	parsed, err := expectedAuditEventsProducerID(managementclient.Target{Host: "example.invalid"}, expected)
	require.NoError(t, err)
	require.Equal(t, expected, parsed.String())
	_, err = expectedAuditEventsProducerID(managementclient.Target{Host: "example.invalid"}, "invalid")
	require.ErrorContains(t, err, "independently trusted")
	require.ErrorContains(t, doRemoteAuditEvents(t.Context(), &managementTarget{}, &management.AuditEventsOptions{ExpectedProducerID: expected}, nil), "--with-sensitive")

	app := kingpin.New("bifroest", "test").Terminate(func(int) {})
	_, options := management.RegisterAuditlogCommands(app, nil, nil, t.Context(), nil, true)
	_, err = app.Parse([]string{"auditlog", "events", "default", "--with-sensitive", "--expectedProducerId=" + expected})
	require.ErrorContains(t, err, "requires a remote target")
	require.Equal(t, expected, options.ExpectedProducerID)
}
