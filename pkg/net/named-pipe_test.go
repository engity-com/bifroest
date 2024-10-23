package net

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNamedPipe(t *testing.T) {
	instance, actualErr := NewNamedPipe("foo")
	require.NoError(t, actualErr)
	require.NotNil(t, instance)
	defer func() {
		require.NoError(t, instance.Close())
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		local, actualErr := instance.AcceptConn()
		assert.NoError(t, actualErr)
		assert.NotNil(t, local)
		defer func() {
			assert.NoError(t, local.Close())
		}()

		n, actualErr := local.Write([]byte("foobar"))
		assert.NoError(t, actualErr)
		assert.Equal(t, 6, n)

		buf := make([]byte, 6)
		n, actualErr = local.Read(buf)
		assert.NoError(t, actualErr)
		assert.Equal(t, 6, n)
		assert.Equal(t, "123456", string(buf))
	}()

	ctx := context.Background()

	remote, actualErr := ConnectToNamedPipe(ctx, instance.Path())
	require.NoError(t, actualErr)
	require.NotNil(t, remote)
	defer func() {
		require.NoError(t, remote.Close())
	}()

	buf := make([]byte, 6)
	n, actualErr := remote.Read(buf)
	require.NoError(t, actualErr)
	require.Equal(t, 6, n)
	require.Equal(t, "foobar", string(buf))

	n, actualErr = remote.Write([]byte("123456"))
	assert.NoError(t, actualErr)
	assert.Equal(t, 6, n)

	wg.Wait()
}
