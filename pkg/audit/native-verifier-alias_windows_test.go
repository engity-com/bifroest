package audit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeVerifierRejectsJunctionIntoJournal(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	nativeTestWriteSealedChain(t, r, journalSegmentSortChunkSize+1)
	alias := filepath.Join(t.TempDir(), "journal-junction")
	if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", alias, conf.Directory).CombinedOutput(); err != nil {
		t.Skipf("cannot create local test junction: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = os.Remove(alias) })
	for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(variable, alias)
	}
	before := snapshotJournalTestTree(t, conf.Directory)
	source := JournalSource{Name: "native", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
	require.ErrorContains(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}), "inside selected journal")
	require.Equal(t, before, snapshotJournalTestTree(t, conf.Directory))
}
