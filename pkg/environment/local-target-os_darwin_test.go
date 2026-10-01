//go:build darwin

package environment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/sys"
)

func TestDarwinLocalTargetOs(t *testing.T) {
	require.Equal(t, sys.OsDarwin, localTargetOs)
}
