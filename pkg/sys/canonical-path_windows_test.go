//go:build windows

package sys

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalPathStopsAtMissingWindowsVolume(t *testing.T) {
	for drive := 'Z'; drive >= 'A'; drive-- {
		root := fmt.Sprintf(`%c:\`, drive)
		if _, err := os.Stat(root); err == nil {
			continue
		}

		_, err := CanonicalPath(root + `missing\tail`)
		require.ErrorContains(t, err, "cannot find existing parent")
		return
	}
	t.Skip("all drive letters are mounted")
}
