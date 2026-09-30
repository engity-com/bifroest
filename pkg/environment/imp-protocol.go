package environment

import (
	"fmt"
	"strconv"

	"github.com/engity-com/bifroest/pkg/imp"
)

func parseImpProtocolRevision(metadata map[string]string, key string) (uint32, error) {
	raw, present := metadata[key]
	if !present {
		return 1, nil
	}
	revision, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || revision == 0 {
		return 0, fmt.Errorf("invalid IMP protocol revision %q in %s", raw, key)
	}
	return uint32(revision), nil
}

func impProtocolCompatible(revision uint32, lifecycle string) bool {
	return revision == imp.ProtocolRevision && lifecycle == executionLifecycleCapability
}

func incompatibleImpResource(resource string, revision uint32, lifecycle string) error {
	if lifecycle != executionLifecycleCapability {
		return fmt.Errorf("existing environment %s does not support execution lifecycle (IMP protocol revision %d); remove it explicitly before retrying", resource, revision)
	}
	return fmt.Errorf("existing environment %s has incompatible IMP protocol revision %d (expected %d); remove it explicitly before retrying", resource, revision, imp.ProtocolRevision)
}
