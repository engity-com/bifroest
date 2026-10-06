package management

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestAuditSnapshotRejectsUnsafeFileNamesBeforeWriting(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"../escape.baudit", "/tmp/escape.baudit", `..\escape.baudit`, "head.cbor/../escape.baudit"} {
		t.Run(name, func(t *testing.T) {
			header := AuditSnapshotHeader{
				Version: 1, Name: "default", Producer: strings.Repeat("a", 64),
				Files: []AuditSnapshotEntry{{Name: name, Size: 1, SHA256: strings.Repeat("0", 64)}},
			}
			encoded, err := cbor.Marshal(header)
			require.NoError(t, err)
			var wire bytes.Buffer
			require.NoError(t, binary.Write(&wire, binary.BigEndian, uint32(len(encoded))))
			_, err = wire.Write(encoded)
			require.NoError(t, err)
			_, err = ReadAuditSnapshot(&wire, root)
			require.ErrorContains(t, err, "invalid audit snapshot file")
			require.NoFileExists(t, filepath.Join(root, "escape.baudit"))
		})
	}
}
