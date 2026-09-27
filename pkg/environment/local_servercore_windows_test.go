//go:build windows && nanoserver_integration

package environment

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestLocalServerCoreAccountFixtureAPIs(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_SERVERCORE_IN_CONTAINER") != "1" {
		t.Skip("only run inside the Server Core local account integration image")
	}
	require.NoError(t, windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserAdd").Find())
}
