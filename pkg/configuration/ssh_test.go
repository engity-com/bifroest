package configuration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
)

func TestSsh_Defaults(t *testing.T) {
	var actual Ssh
	require.NoError(t, yaml.Unmarshal([]byte("{}"), &actual))

	assert.Equal(t, 30*time.Second, actual.GracefulShutdownTimeout.Native())
	assert.Equal(t, 2*time.Minute, actual.HandshakeTimeout.Native())
	assert.Equal(t, 30*time.Second, actual.SessionRequestTimeout.Native())
	assert.Equal(t, uint16(10), actual.MaxStartupsStart)
	assert.Equal(t, uint8(30), actual.MaxStartupsRate)
	assert.Equal(t, uint16(100), actual.MaxStartupsFull)
	assert.Equal(t, uint16(10), actual.MaxSessionsPerConnection)
	assert.Equal(t, uint16(64), actual.MaxChannelsPerConnection)
	assert.Equal(t, uint16(16), actual.MaxReverseForwardsPerConnection)
	assert.Equal(t, uint16(64), actual.MaxChannels)
	assert.Equal(t, uint16(256), actual.MaxReverseForwards)
	assert.Equal(t, time.Minute, actual.UnauthenticatedAudit.Interval.Native())
	assert.Equal(t, uint16(6), actual.UnauthenticatedAudit.PerSourceLimit)
	assert.Equal(t, uint16(24), actual.UnauthenticatedAudit.GlobalLimit)
}

func TestSshUnauthenticatedAuditConfiguration(t *testing.T) {
	var actual Ssh
	require.NoError(t, yaml.Unmarshal([]byte(`
unauthenticatedAudit:
  interval: 30s
  perSourceLimit: 3
  globalLimit: 9
`), &actual))
	require.Equal(t, 30*time.Second, actual.UnauthenticatedAudit.Interval.Native())
	require.Equal(t, uint16(3), actual.UnauthenticatedAudit.PerSourceLimit)
	require.Equal(t, uint16(9), actual.UnauthenticatedAudit.GlobalLimit)
	require.True(t, actual.UnauthenticatedAudit.IsEqualTo(SshUnauthenticatedAudit{
		Interval: common.DurationOf(30 * time.Second), PerSourceLimit: 3, GlobalLimit: 9,
	}))

	for _, input := range []string{
		"interval: 0",
		"perSourceLimit: 0",
		"perSourceLimit: 4\nglobalLimit: 3",
		"unknown: true",
	} {
		var invalid SshUnauthenticatedAudit
		require.Error(t, yaml.Unmarshal([]byte(input), &invalid), input)
	}
}

func TestSsh_ExplicitZeroValues(t *testing.T) {
	var actual Ssh
	require.NoError(t, yaml.Unmarshal([]byte(`
gracefulShutdownTimeout: 0
handshakeTimeout: 0
sessionRequestTimeout: 0
maxStartupsStart: 0
maxStartupsRate: 0
maxStartupsFull: 0
maxSessionsPerConnection: 0
maxChannelsPerConnection: 0
maxReverseForwardsPerConnection: 0
maxChannels: 0
maxReverseForwards: 0
`), &actual))

	assert.Equal(t, time.Duration(0), actual.GracefulShutdownTimeout.Native())
	assert.Equal(t, time.Duration(0), actual.HandshakeTimeout.Native())
	assert.Equal(t, time.Duration(0), actual.SessionRequestTimeout.Native())
	assert.Equal(t, uint16(0), actual.MaxStartupsStart)
	assert.Equal(t, uint8(0), actual.MaxStartupsRate)
	assert.Equal(t, uint16(0), actual.MaxStartupsFull)
	assert.Equal(t, uint16(0), actual.MaxSessionsPerConnection)
	assert.Equal(t, uint16(0), actual.MaxChannelsPerConnection)
	assert.Equal(t, uint16(0), actual.MaxReverseForwardsPerConnection)
	assert.Equal(t, uint16(0), actual.MaxChannels)
	assert.Equal(t, uint16(0), actual.MaxReverseForwards)
}

func TestSsh_InvalidMaxStartups(t *testing.T) {
	for _, test := range []struct {
		name          string
		yaml          string
		expectedError string
	}{
		{
			name:          "rate-above-100",
			yaml:          "maxStartupsRate: 101",
			expectedError: "[maxStartupsRate] must be less than or equal to 100",
		},
		{
			name: "start-above-full",
			yaml: `
maxStartupsStart: 11
maxStartupsFull: 10
`,
			expectedError: "[maxStartupsFull] must be greater than or equal to maxStartupsStart",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var actual Ssh
			assert.ErrorContains(t, yaml.Unmarshal([]byte(test.yaml), &actual), test.expectedError)
		})
	}
}

func TestSsh_MaxStartupsFullZeroDisablesLimit(t *testing.T) {
	var actual Ssh
	require.NoError(t, yaml.Unmarshal([]byte("maxStartupsFull: 0"), &actual))

	assert.Equal(t, DefaultSshMaxStartupsStart, actual.MaxStartupsStart)
	assert.Equal(t, uint16(0), actual.MaxStartupsFull)
}

func TestSsh_RejectsNegativeTimeouts(t *testing.T) {
	for _, field := range []string{"idleTimeout", "maxTimeout", "gracefulShutdownTimeout", "handshakeTimeout", "sessionRequestTimeout"} {
		t.Run(field, func(t *testing.T) {
			var actual Ssh
			assert.ErrorContains(t, yaml.Unmarshal([]byte(field+": -1s"), &actual), "["+field+"] must be greater than or equal to 0")
		})
	}
}
