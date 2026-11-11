package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/management/wire"
)

func TestLegacyManagementAdaptersUsePortableV1Framing(t *testing.T) {
	encoded, err := EncodeWireRequest([]string{"flow", "ls"})
	require.NoError(t, err)
	require.Equal(t, "a20101028264666c6f77626c73", hex.EncodeToString(encoded))
	args, err := wire.DecodeWireRequest(bytes.NewReader(encoded))
	require.NoError(t, err)
	require.Equal(t, []string{"flow", "ls"}, args)
	var stream bytes.Buffer
	entry := model.RecordingView{ID: "fixture"}
	require.NoError(t, WriteRecordingStreamEntry(&stream, entry))
	require.NoError(t, WriteRecordingStreamEnd(&stream, 1))
	var seen []protocol.RecordingView
	require.NoError(t, wire.DecodeRecordingListStream(&stream, func(row protocol.RecordingView) error { seen = append(seen, row); return nil }))
	require.Equal(t, []protocol.RecordingView{entry}, seen)
}

func TestNativeAuditSinkWritesOnlyValidatedPortableEntriesAndNeverOverwrites(t *testing.T) {
	root := t.TempDir()
	producer := strings.Repeat("a", 64)
	const payload = "opaque evidence bytes"
	header := AuditSnapshotHeader{Version: 1, Name: "default", Producer: producer, Files: []AuditSnapshotEntry{{Name: "head.cbor", Size: int64(len(payload)), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))}}}
	var encoded bytes.Buffer
	require.NoError(t, wire.WriteAuditSnapshotHeader(&encoded, header))
	encoded.WriteString(payload)
	decoded, err := ReadAuditSnapshot(bytes.NewReader(encoded.Bytes()), root)
	require.NoError(t, err)
	require.Equal(t, header, decoded)
	path := filepath.Join(root, "journal", producer, "head.cbor")
	file, err := os.Open(path)
	require.NoError(t, err)
	content, err := io.ReadAll(file)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	require.Equal(t, payload, string(content))
	_, err = ReadAuditSnapshot(bytes.NewReader(encoded.Bytes()), root)
	require.Error(t, err)
	content, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, payload, string(content))
}
