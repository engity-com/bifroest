package protocol

import (
	"context"
	gonet "net"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/execution"
)

func TestReadExecutionExitCodeKeepsSuccessfulResultForRetry(t *testing.T) {
	directory := t.TempDir()
	executionId := connection.MustNewId()
	path := filepath.Join(directory, executionId.String())
	require.NoError(t, os.WriteFile(path, []byte("23\n"), 0600))

	exitCode, err := readExecutionExitCode(directory, executionId)
	require.NoError(t, err)
	require.Equal(t, 23, exitCode)
	require.FileExists(t, path)
	exitCode, err = readExecutionExitCode(directory, executionId)
	require.NoError(t, err)
	require.Equal(t, 23, exitCode)
}

func TestReadExecutionExitCodeRejectsAndRemovesInvalidResult(t *testing.T) {
	directory := t.TempDir()
	executionId := connection.MustNewId()
	path := filepath.Join(directory, executionId.String())
	require.NoError(t, os.WriteFile(path, []byte("not-an-exit-code"), 0600))

	_, err := readExecutionExitCode(directory, executionId)
	require.Error(t, err)
	require.False(t, errors.Is(err, connection.ErrNotFound))
	require.NoFileExists(t, path)
}

func TestGetExecutionExitCodeTransportFailureKeepsResult(t *testing.T) {
	directory := t.TempDir()
	executionDirectory := filepath.Join(directory, execution.StateDirectoryName)
	require.NoError(t, os.MkdirAll(executionDirectory, 0700))
	connectionId := connection.MustNewId()
	executionId := connection.MustNewId()
	path := filepath.Join(executionDirectory, executionId.String())
	require.NoError(t, os.WriteFile(path, []byte("42"), 0600))

	server, client := gonet.Pipe()
	serverConn := codec.NewMsgPackConn(server)
	clientConn := codec.NewMsgPackConn(client)
	handlerDone := make(chan error, 1)
	go func() {
		handlerDone <- (&imp{Imp: &Imp{ExitCodeByConnectionIdPath: directory}}).handleMethodGetExecutionExitCode(
			context.Background(),
			&Header{Method: MethodGetExecutionExitCode, ConnectionId: connectionId},
			log.GetLogger("test"),
			serverConn,
		)
	}()
	require.NoError(t, (methodGetExecutionExitCodeRequest{executionId: executionId}).EncodeMsgPack(clientConn))
	require.NoError(t, client.Close())
	require.Error(t, <-handlerDone)
	require.FileExists(t, path)
}

func TestGetExecutionExitCodeRemovesDeliveredResult(t *testing.T) {
	directory := t.TempDir()
	executionDirectory := filepath.Join(directory, execution.StateDirectoryName)
	require.NoError(t, os.MkdirAll(executionDirectory, 0700))
	connectionId := connection.MustNewId()
	executionId := connection.MustNewId()
	path := filepath.Join(executionDirectory, executionId.String())
	require.NoError(t, os.WriteFile(path, []byte("42"), 0600))

	server, client := gonet.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	serverConn := codec.NewMsgPackConn(server)
	clientConn := codec.NewMsgPackConn(client)
	handlerDone := make(chan error, 1)
	go func() {
		handlerDone <- (&imp{Imp: &Imp{ExitCodeByConnectionIdPath: directory}}).handleMethodGetExecutionExitCode(
			context.Background(),
			&Header{Method: MethodGetExecutionExitCode, ConnectionId: connectionId},
			log.GetLogger("test"),
			serverConn,
		)
	}()

	require.NoError(t, (methodGetExecutionExitCodeRequest{executionId: executionId}).EncodeMsgPack(clientConn))
	var response methodGetConnectionExitCodeResponse
	require.NoError(t, response.DecodeMsgPack(clientConn))
	require.True(t, response.found)
	require.Equal(t, 42, response.exitCode)
	require.NoError(t, response.error)
	require.NoError(t, clientConn.EncodeBool(true))
	require.NoError(t, <-handlerDone)
	require.NoFileExists(t, path)
}

func TestGetConnectionExitCodeKeepsLegacyWireBehavior(t *testing.T) {
	directory := t.TempDir()
	connectionId := connection.MustNewId()
	require.NoError(t, os.WriteFile(filepath.Join(directory, connectionId.String()), []byte("17"), 0600))

	server, client := gonet.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	serverConn := codec.NewMsgPackConn(server)
	clientConn := codec.NewMsgPackConn(client)
	handlerDone := make(chan error, 1)
	go func() {
		handlerDone <- (&imp{Imp: &Imp{ExitCodeByConnectionIdPath: directory}}).handleMethodGetConnectionExitCode(
			context.Background(),
			&Header{Method: MethodGetConnectionExitCode, ConnectionId: connectionId},
			log.GetLogger("test"),
			serverConn,
		)
	}()

	require.NoError(t, (methodGetConnectionExitCodeRequest{}).EncodeMsgPack(clientConn))
	var response methodGetConnectionExitCodeResponse
	require.NoError(t, response.DecodeMsgPack(clientConn))
	require.True(t, response.found)
	require.Equal(t, 17, response.exitCode)
	require.NoError(t, response.error)
	require.NoError(t, <-handlerDone)
}

func TestCleanupStaleExecutionResultsIsBoundedAndSkipsCurrentResult(t *testing.T) {
	directory := t.TempDir()
	current := connection.MustNewId()
	stale := connection.MustNewId()
	recent := connection.MustNewId()
	now := time.Now()
	for _, id := range []connection.Id{current, stale, recent} {
		require.NoError(t, os.WriteFile(filepath.Join(directory, id.String()), []byte("0"), 0600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(directory, stale.String()+".pid"), []byte("1"), 0600))
	require.NoError(t, os.Chtimes(filepath.Join(directory, current.String()), now.Add(-2*executionResultRetention), now.Add(-2*executionResultRetention)))
	require.NoError(t, os.Chtimes(filepath.Join(directory, stale.String()), now.Add(-2*executionResultRetention), now.Add(-2*executionResultRetention)))
	require.NoError(t, os.Chtimes(filepath.Join(directory, stale.String()+".pid"), now.Add(-2*executionResultRetention), now.Add(-2*executionResultRetention)))

	cleanupStaleExecutionResults(directory, current, now)

	require.FileExists(t, filepath.Join(directory, current.String()))
	require.NoFileExists(t, filepath.Join(directory, stale.String()))
	require.FileExists(t, filepath.Join(directory, recent.String()))
	require.NoFileExists(t, filepath.Join(directory, stale.String()+".pid"))
}

func TestExecutionCleanupDoesNotRemoveLegacyResult(t *testing.T) {
	directory := t.TempDir()
	executionDirectory := filepath.Join(directory, execution.StateDirectoryName)
	require.NoError(t, os.MkdirAll(executionDirectory, 0700))
	legacy := connection.MustNewId()
	current := connection.MustNewId()
	legacyPath := filepath.Join(directory, legacy.String())
	require.NoError(t, os.WriteFile(legacyPath, []byte("11"), 0600))
	require.NoError(t, os.Chtimes(legacyPath, time.Now().Add(-2*executionResultRetention), time.Now().Add(-2*executionResultRetention)))
	require.NoError(t, os.WriteFile(filepath.Join(executionDirectory, current.String()), []byte("12"), 0600))

	response := (&imp{Imp: &Imp{ExitCodeByConnectionIdPath: directory}}).getExecutionExitCode(current)

	require.NoError(t, response.error)
	require.True(t, response.found)
	require.Equal(t, 12, response.exitCode)
	require.FileExists(t, legacyPath)
}

func TestExecutionCleanupBoundsRetainedResults(t *testing.T) {
	directory := t.TempDir()
	now := time.Now()
	ids := []connection.Id{connection.MustNewId(), connection.MustNewId(), connection.MustNewId()}
	for i, id := range ids {
		path := filepath.Join(directory, id.String())
		require.NoError(t, os.WriteFile(path, []byte("0"), 0600))
		modified := now.Add(time.Duration(i) * time.Second)
		require.NoError(t, os.Chtimes(path, modified, modified))
	}

	cleanupExecutionResults(directory, connection.Id{}, now.Add(10*time.Second), 2)

	require.NoFileExists(t, filepath.Join(directory, ids[0].String()))
	require.FileExists(t, filepath.Join(directory, ids[1].String()))
	require.FileExists(t, filepath.Join(directory, ids[2].String()))
}
