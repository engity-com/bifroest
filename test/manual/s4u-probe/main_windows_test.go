//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/test/nanoserver/browserfixture"
)

func TestContainerAccountCreationRejectsHost(t *testing.T) {
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	if sid == "S-1-5-93-2-1" {
		t.Skip("requires an ordinary Windows host identity")
	}
	t.Setenv("BIFROEST_TEST_LOCAL_SAM_IN_CONTAINER", "1")
	_, err = prepareContainerTestUser()
	if err == nil || !strings.Contains(err.Error(), "requires ContainerAdministrator") {
		t.Fatalf("expected host account creation to be rejected, got %v", err)
	}
}

func TestBrowserBootstrapRejectsHostBeforeNativeChanges(t *testing.T) {
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	if sid == "S-1-5-93-2-1" {
		t.Skip("requires an ordinary Windows host identity")
	}
	t.Setenv("BIFROEST_TEST_SERVERCORE_BROWSER", "1")
	t.Setenv("BIFROEST_TEST_LOCAL_SAM_IN_CONTAINER", "1")
	_, err = prepareBrowserConfiguration("must-not-be-opened.exe")
	if err == nil || !strings.Contains(err.Error(), "ContainerAdministrator") {
		t.Fatalf("expected host bootstrap rejection before account/service/file changes, got %v", err)
	}
}

func TestBrowserFixtureConfigurationAndRealCliPreflight(t *testing.T) {
	root := t.TempDir()
	const name = "bifroest-native-test"
	const sid = "S-1-5-21-1-2-3-1001"
	path := filepath.Join(root, "configuration.yaml")
	require.NoError(t, os.WriteFile(path, []byte(browserConfiguration(root, name, sid)), 0600))
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromFile(path))
	require.Len(t, conf.Flows, 1)
	local := conf.Flows[0].Environment.V.(*configuration.EnvironmentLocal)
	user, err := local.Name.Render(nil)
	require.NoError(t, err)
	require.Equal(t, name, user)
	uid, err := local.Uid.Render(nil)
	require.NoError(t, err)
	require.Equal(t, sid, uid)
	require.NoError(t, preflightBrowserService(browserfixture.Fixture{Root: root, Service: "bifroest-browser-cli-preflight"}))
}

func TestSystemBrowserDiagnosticsAreExplicitServiceArguments(t *testing.T) {
	t.Setenv("BIFROEST_TEST_SERVERCORE_BROWSER_DIAGNOSTICS", "")
	require.Equal(t, []string{"service", "owned", "result", "tests", "user", "servercore", "browser-diagnostics"}, probeServiceArguments("owned", "result", "tests", "user", true, true))
	require.Equal(t, []string{"service", "owned", "result", "tests", "user", "servercore"}, probeServiceArguments("owned", "result", "tests", "user", true, false))
	require.Equal(t, []string{"service", "owned", "result", "tests", "user"}, probeServiceArguments("owned", "result", "tests", "user", false, true))
}
