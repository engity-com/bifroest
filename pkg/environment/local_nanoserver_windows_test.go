//go:build windows && nanoserver_integration

package environment

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestLocalNanoServerDLLExports(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_NANOSERVER_IN_CONTAINER") != "1" {
		t.Skip("only run in the pinned Nano Server integration image")
	}
	for _, library := range []struct {
		name  string
		procs []string
	}{
		{"secur32.dll", []string{"LsaRegisterLogonProcess", "LsaLookupAuthenticationPackage", "LsaLogonUser", "LsaDeregisterLogonProcess", "LsaFreeReturnBuffer"}},
		{"advapi32.dll", []string{"AllocateLocallyUniqueId", "CreateProcessAsUserW"}},
		{"userenv.dll", []string{"LoadUserProfileW", "UnloadUserProfile", "CreateProfile", "CreateEnvironmentBlock", "GetUserProfileDirectoryW"}},
		{"netapi32.dll", []string{"NetUserAdd"}},
		{"kernel32.dll", []string{"CreatePseudoConsole", "ResizePseudoConsole", "ClosePseudoConsole"}},
	} {
		t.Run(library.name, func(t *testing.T) {
			dll := windows.NewLazySystemDLL(library.name)
			for _, proc := range library.procs {
				require.NoError(t, dll.NewProc(proc).Find(), "%s!%s", library.name, proc)
			}
		})
	}
}
