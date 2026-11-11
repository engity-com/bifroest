package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/engity-com/bifroest/pkg/uuidtext"
)

// ResolveRecordingFileName is a metadata-only lookup of the two possible receipt
// state directory names. It does not create a directory, load/repair a receipt or
// attest signatures. Require/Stage/Prepare retain all their existing validation,
// ownership, quota and durable-state contracts after this lookup.
func (r *RemoteArtifactReceipts) ResolveRecordingFileName(input string) (string, bool, error) {
	if r == nil || r.store == nil {
		return "", false, fmt.Errorf("nil recording receipt store")
	}
	suffix := ""
	for _, candidate := range []string{".bcast", ".becast"} {
		if strings.HasSuffix(input, candidate) {
			suffix = candidate
			break
		}
	}
	if suffix == "" {
		return "", false, fmt.Errorf("invalid recording receipt suffix")
	}
	id, err := uuidtext.Parse(strings.TrimSuffix(input, suffix))
	if err != nil || id == [16]byte{} {
		return "", false, fmt.Errorf("invalid recording receipt ID")
	}
	current, legacy := uuidtext.Format(id)+suffix, uuidtext.Classic(id)+suffix
	name, found := current, false
	for _, candidate := range []string{current, legacy} {
		path := filepath.Join(r.store.producerDirectory, remoteArtifactReceiptStateName(candidate))
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", false, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", false, fmt.Errorf("invalid recording receipt state directory")
		}
		if found {
			return "", false, fmt.Errorf("ambiguous recording receipt filename aliases")
		}
		name, found = candidate, true
	}
	return name, found, nil
}
