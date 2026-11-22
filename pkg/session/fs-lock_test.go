package session

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestFsRepositoryProcessLockIsExclusiveAndRemovedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repository.lock")
	lock, err := acquireFsRepositoryProcessLock(path, 0600)
	require.NoError(t, err)
	require.FileExists(t, path)

	_, err = acquireFsRepositoryProcessLock(path, 0600)
	require.Error(t, err)
	require.NoError(t, lock.Close())
	require.NoError(t, lock.Close())
	require.NoFileExists(t, path)

	reopened, err := acquireFsRepositoryProcessLock(path, 0600)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
	require.NoFileExists(t, path)
}

func TestFsRepositorySingleWriterAcrossProcessesAndAbruptExit(t *testing.T) {
	const storageEnv = "BIFROEST_TEST_SINGLE_WRITER_STORAGE"
	if storage := os.Getenv(storageEnv); storage != "" {
		conf := &configuration.SessionFs{}
		require.NoError(t, conf.SetDefaults())
		conf.Storage = storage
		repository, err := NewFsRepository(t.Context(), conf)
		require.NoError(t, err)
		created, err := repository.Create(t.Context(), "test", fsRepositoryTestRemote{}, []byte("authorization"))
		require.NoError(t, err)
		require.NoError(t, created.SetEnvironmentToken(t.Context(), []byte("retained-workspace-reference")))
		fmt.Println(created.Id())
		// The parent terminates this process without Close: only the operating
		// system can release the lock, and the repository state must remain.
		<-t.Context().Done()
		return
	}

	conf := newFsRepositoryTestConfiguration(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFsRepositorySingleWriterAcrossProcessesAndAbruptExit$", "-test.timeout=30s")
	child.Env = append(os.Environ(), storageEnv+"="+conf.Storage)
	child.Stderr = os.Stderr
	stdout, err := child.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, child.Start())
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	require.NoError(t, err)
	var id Id
	require.NoError(t, id.Set(strings.TrimSpace(line)))

	_, err = NewFsRepository(t.Context(), conf)
	require.ErrorContains(t, err, "already locked")
	require.NoError(t, child.Process.Kill())
	err = child.Wait()
	waited = true
	require.Error(t, err)
	require.NoError(t, ctx.Err(), "the process must be terminated deliberately, not by a timeout")

	reopened, err := NewFsRepository(t.Context(), conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	restored, err := reopened.FindBy(t.Context(), "test", id, nil)
	require.NoError(t, err)
	token, err := restored.EnvironmentToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, "retained-workspace-reference", string(token))
}
