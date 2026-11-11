package recording

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/engity-com/bifroest/pkg/uuidpath"
)

// ArtifactFileName resolves only bounded filesystem metadata. It neither opens
// recordings nor repairs repositories. The returned name is NOT verified
// evidence or permission: the consuming operation must still verify its bytes,
// signing identity, receipts and caller policy. Immutable legacy names stay bound
// to their original signed lifecycle/delivery receipts.
func (r *LocalNativeRecordingRepository) ArtifactFileName(id Id) (string, bool, error) {
	if r == nil || r.repository == nil {
		return "", false, fmt.Errorf("nil recording repository")
	}
	if err := validateId(id); err != nil {
		return "", false, err
	}
	suffix := r.repository.format.sealedSuffix()
	name := id.String() + suffix
	found := false
	for _, item := range []struct{ directory, suffix string }{{r.repository.sealedPath, suffix}, {r.repository.activePath, ""}, {r.repository.workPath, ".tmp"}} {
		path, exists, err := uuidpath.ResolveExisting(item.directory, id, item.suffix)
		if err != nil {
			return "", false, err
		}
		if !exists {
			continue
		}
		candidate := strings.TrimSuffix(filepath.Base(path), item.suffix) + suffix
		if found && name != candidate {
			return "", false, fmt.Errorf("ambiguous recording storage aliases across active, staged and sealed state")
		}
		name, found = candidate, true
	}
	return name, found, nil
}
