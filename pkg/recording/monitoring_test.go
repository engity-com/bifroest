package recording

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/errors"
)

func TestSpoolUsageReportsReservationsAndUncertainAccounting(t *testing.T) {
	quota := &localQuota{maximum: 4096}
	repository := &LocalNativeRecordingRepository{repository: &localRepository[[]byte, NativeRecordingSummary]{quota: quota}}
	usage, valid := repository.SpoolUsage()
	require.True(t, valid)
	require.Zero(t, usage)
	require.NoError(t, quota.reserve(4096))
	usage, valid = repository.SpoolUsage()
	require.True(t, valid)
	require.EqualValues(t, 4096, usage)
	require.Error(t, quota.reserve(1))
	usage, valid = repository.SpoolUsage()
	require.True(t, valid)
	require.EqualValues(t, 4096, usage)
	require.NoError(t, quota.release(2048))
	usage, valid = repository.SpoolUsage()
	require.True(t, valid)
	require.EqualValues(t, 2048, usage)
	quota.Invalidate(errors.System.Newf("accounting unavailable"))
	_, valid = repository.SpoolUsage()
	require.False(t, valid)
}

func TestSpoolUsageConcurrentReservations(t *testing.T) {
	quota := &localQuota{maximum: 4096}
	repository := &LocalNativeRecordingRepository{repository: &localRepository[[]byte, NativeRecordingSummary]{quota: quota}}
	var wait sync.WaitGroup
	for range 4 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 100 {
				if err := quota.reserve(1); err != nil {
					t.Error(err)
					return
				}
				_, _ = repository.SpoolUsage()
				if err := quota.release(1); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wait.Wait()
	usage, valid := repository.SpoolUsage()
	require.True(t, valid)
	require.Zero(t, usage)
}
