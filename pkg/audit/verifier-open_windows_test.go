package audit

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestWindowsNativeHeadReplacementWithOpenVerifier(t *testing.T) {
	testWindowsNativeHeadReplacementWithOpenVerifier(t, t.TempDir())
}

func TestWindowsNativeHeadReplacementOnReFS(t *testing.T) {
	root := os.Getenv("BIFROEST_AUDIT_TEST_REFS_ROOT")
	if root == "" {
		t.Skip("set BIFROEST_AUDIT_TEST_REFS_ROOT to a writable ReFS directory")
	}
	info, err := os.Stat(root)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	path, err := windows.UTF16PtrFromString(root)
	require.NoError(t, err)
	volume := make([]uint16, 1024)
	require.NoError(t, windows.GetVolumePathName(path, &volume[0], uint32(len(volume))))
	var fileSystem [64]uint16
	var flags uint32
	require.NoError(t, windows.GetVolumeInformation(&volume[0], nil, 0, nil, nil, &flags, &fileSystem[0], uint32(len(fileSystem))))
	require.Equal(t, "ReFS", windows.UTF16ToString(fileSystem[:]))
	t.Logf("ReFS FILE_SUPPORTS_POSIX_UNLINK_RENAME: %t", flags&0x400 != 0)
	directory, err := os.MkdirTemp(root, "bifroest-audit-refs-*")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(directory)) })
	testWindowsNativeHeadReplacementWithOpenVerifier(t, directory)
	conf, id := nativeRecorderTestConfig(t, false)
	conf.Directory = filepath.Join(directory, "journal")
	r := nativeTestOpen(t, &conf, id)
	defer func() { require.NoError(t, r.CloseAfterAcceptedFailure()) }()
	require.NoError(t, r.Record(context.Background(), Event{Name: "first"}))
	head, err := openVerifierPath(filepath.Join(r.headDirectory, nativeHeadFileName))
	require.NoError(t, err)
	defer func() { require.NoError(t, head.Close()) }()
	active, err := openVerifierPath(r.activePath)
	require.NoError(t, err)
	defer func() { require.NoError(t, active.Close()) }()
	require.NoError(t, r.Record(context.Background(), Event{Name: "second"}))
	require.NoError(t, r.Seal())
	source := JournalSource{Name: "refs", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
	verification, err := VerifyLiveJournals(context.Background(), []JournalSource{source})
	require.NoError(t, err)
	require.Len(t, verification.Records(), 2)
}

func testWindowsNativeHeadReplacementWithOpenVerifier(t *testing.T, directory string) {
	t.Helper()
	target := filepath.Join(directory, "head.cbor")
	temporary := filepath.Join(directory, ".head-cbor-123456")
	require.NoError(t, os.WriteFile(target, []byte("old head"), 0600))
	require.NoError(t, os.WriteFile(temporary, []byte("new head"), 0600))
	reader, err := openVerifierPath(target)
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()
	require.NoError(t, replaceNativeHeadFile(temporary, target))
	old, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, []byte("old head"), old)
	current, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, []byte("new head"), current)
	require.False(t, bytes.Equal(old, current))
	require.NoFileExists(t, temporary)
}
