package audit

import (
	"bytes"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/echocat/cli4g/codec"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/managementclient"
)

func TestSensitiveAuditEventsRequireExplicitTrustAnchorAndRemoteTarget(t *testing.T) {
	const expected = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	parsed, err := expectedAuditEventsProducerID(managementclient.Target{Host: "example.invalid"}, expected)
	require.NoError(t, err)
	require.Equal(t, expected, parsed.String())
	_, err = expectedAuditEventsProducerID(managementclient.Target{Host: "example.invalid"}, "invalid")
	require.ErrorContains(t, err, "independently trusted")
	require.ErrorContains(t, doRemoteAuditEvents(t.Context(), managementclient.Target{Host: "example.invalid"},
		AuditEventsOptions{ExpectedProducerID: expected}, nil), "--with-sensitive")

	requirement := cli.NewSimpleApplication().WithName("bifroest").
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false).
		WithCodec(codec.NewDateTime().WithFormats(time.RFC3339), "rfc3339")
	Register(t.Context(), requirement, common.UsageExecutable)
	app, err := requirement.Create()
	require.NoError(t, err)
	defer func() { require.NoError(t, app.Close()) }()
	var output bytes.Buffer
	ctx := cli.ContextWithStdio(t.Context(), nil, &output, nil)
	err = app.ParseAndExecute(ctx, nil, "audit", "events", "default", "--with-sensitive", "--expectedProducerId="+expected)
	require.ErrorContains(t, err, "requires a remote target")
	require.Empty(t, output.String())
}
