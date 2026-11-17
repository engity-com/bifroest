//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestBrowserPreparationReadSharesPublisherDeleteHandleWithoutRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public-result.json")
	name, err := windows.UTF16PtrFromString(path)
	require.NoError(t, err)
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	require.NoError(t, err)
	publisher := os.NewFile(uintptr(handle), path)
	t.Cleanup(func() { require.NoError(t, publisher.Close()) })
	wanted := []byte(`{"Fixture":{"Service":"exact-owned-service"},"Error":""}`)
	written, err := publisher.Write(wanted)
	require.NoError(t, err)
	require.Equal(t, len(wanted), written)
	require.NoError(t, publisher.Sync())
	// This is the precise conflicting handle state during Rename publication,
	// without depending on scheduler timing, an added retry or a longer limit.
	_, err = os.ReadFile(path)
	require.ErrorIs(t, err, windows.ERROR_SHARING_VIOLATION)
	actual, err := readBrowserPreparationResultFile(path)
	require.NoError(t, err)
	require.Equal(t, wanted, actual)
}

func TestBrowserPreparationResultReadDoesNotCreateMissingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-result.json")
	raw, err := readBrowserPreparationResultFile(path)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Nil(t, raw)
	require.NoFileExists(t, path)
}
