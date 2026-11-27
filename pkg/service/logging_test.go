package service

import (
	"testing"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/sdk/testlog"
	"github.com/echocat/slf4g/testing/recording"
	"github.com/stretchr/testify/require"
)

func hookServiceTestLog(t *testing.T) {
	t.Helper()
	// Tests that inspect log events install their own recording provider.
	if _, ok := log.UnwrapProvider(log.GetProvider()).(*recording.Provider); ok {
		return
	}

	// Failure-policy tests deliberately trigger error logs and assert their
	// effects themselves. Keep those logs without failing on their level alone.
	testlog.Hook(t, testlog.FailAtLevel(testlog.NeverFailLevel))
}

func TestHookServiceTestLogInstallsAndRestoresProvider(t *testing.T) {
	previous := log.UnwrapProvider(log.GetProvider())
	t.Run("test logger", func(t *testing.T) {
		hookServiceTestLog(t)
		require.IsType(t, &testlog.Provider{}, log.UnwrapProvider(log.GetProvider()))
		log.Info("test output uses testing.T")
		log.Error("failure-policy tests may deliberately log errors")
	})
	require.Same(t, previous, log.UnwrapProvider(log.GetProvider()))
}

func TestHookServiceTestLogPreservesRecordingProvider(t *testing.T) {
	provider := recording.NewProvider()
	t.Cleanup(provider.HookGlobally())

	hookServiceTestLog(t)
	require.Same(t, provider, log.UnwrapProvider(log.GetProvider()))
	log.Info("log assertions retain their recording provider")
	require.Equal(t, 1, provider.Len())
}
