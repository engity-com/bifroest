package session

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
)

func TestFsActivityCheckIsReadOnlyAndCannotReviveExpiredIdle(t *testing.T) {
	conf := newFsRepositoryTestConfiguration(t)
	conf.IdleTimeout = common.DurationOf(time.Second)
	repo, err := NewFsRepository(t.Context(), conf)
	require.NoError(t, err)
	defer repo.Close()
	sess, err := repo.Create(t.Context(), "test", fsRepositoryTestRemote{}, []byte("credentials"))
	require.NoError(t, err)
	lease, err := sess.ConnectionInterceptor(t.Context())
	require.NoError(t, err)
	defer lease.Close()
	activity := lease.(ActivityInterceptor)
	before, _, err := activity.Check(t.Context())
	require.NoError(t, err)
	for range 5 {
		after, _, err := activity.Check(t.Context())
		require.NoError(t, err)
		require.Equal(t, before, after)
	}
	path, err := repo.file(sess.Flow(), sess.Id(), FsFileLastAccessed)
	require.NoError(t, err)
	past := time.Now().Add(-2 * time.Second)
	require.NoError(t, os.Chtimes(path, past, past))
	deadline, result, err := activity.OnActivity(t.Context())
	require.NoError(t, err)
	require.Equal(t, ConnectionInterceptorResultIdle, result)
	require.True(t, deadline.Before(time.Now()))
	stat, err := os.Stat(path)
	require.NoError(t, err)
	require.WithinDuration(t, past, stat.ModTime(), time.Millisecond)
}

func TestFsActivityVisibleAcrossSshAndNeutralLeasesBeforeDiskTouch(t *testing.T) {
	conf := newFsRepositoryTestConfiguration(t)
	conf.IdleTimeout = common.DurationOf(time.Hour)
	repo, err := NewFsRepository(t.Context(), conf)
	require.NoError(t, err)
	defer repo.Close()
	sess, err := repo.Create(t.Context(), "test", fsRepositoryTestRemote{}, []byte("credentials"))
	require.NoError(t, err)
	ssh, err := sess.ConnectionInterceptor(t.Context())
	require.NoError(t, err)
	defer ssh.Close()
	neutral, err := sess.ConnectionInterceptor(t.Context())
	require.NoError(t, err)
	defer neutral.Close()
	stack := ssh.(*fsConnectionInterceptor).fsConnectionInterceptorStack
	future := time.Now().Add(time.Minute).UnixMilli()
	stack.observedActivity.Store(future)
	deadline, _, err := neutral.(ActivityInterceptor).Check(t.Context())
	require.NoError(t, err)
	info, err := sess.Info(t.Context())
	require.NoError(t, err)
	visible, err := info.ValidUntil(t.Context())
	require.NoError(t, err)
	require.Equal(t, deadline, visible)
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 20 {
				_, _, _ = stack.onConnectionAction()
			}
		}()
	}
	group.Wait()
	require.Equal(t, future, stack.observedActivity.Load(), "out-of-order activity must not roll back the observed time")
}
