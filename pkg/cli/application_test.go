package cli

import (
	"bytes"
	"context"
	"sync"
	"testing"

	clibase "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

type testApplications struct {
	Executable *clibase.Application[clibase.NoOptions]
	Management *clibase.Application[clibase.NoOptions]
}

func newTestApplications(t *testing.T) testApplications {
	t.Helper()
	executable, err := NewApplication[clibase.NoOptions](nil, "", nil).Create()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, executable.Close()) })
	management, err := NewApplication[clibase.NoOptions](nil, "Bifröst SSH management.", nil).Create()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, management.Close()) })
	return testApplications{executable, management}
}

func TestBuildsSeparateReusableApplications(t *testing.T) {
	apps := newTestApplications(t)
	type executor interface {
		ParseAndExecute(context.Context, *clibase.ParseOpts, ...string) error
	}
	for _, application := range []struct {
		app     executor
		profile string
		args    []string
	}{
		{apps.Executable, common.ProfileExecutable, []string{"key", "--help"}},
		{apps.Management, common.ProfileManagement, []string{"audit", "--help"}},
		{apps.Management, common.ProfileManagement, []string{"session", "--help"}},
	} {
		var output, diagnostic bytes.Buffer
		ctx := clibase.ContextWithStdio(t.Context(), nil, &output, &diagnostic)
		require.NoError(t, application.app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{application.profile}}, application.args...))
		require.NotEmpty(t, output.String()+diagnostic.String())
	}
	var output bytes.Buffer
	ctx := clibase.ContextWithStdio(t.Context(), nil, &output, nil)
	_, found := apps.Management.CommandOfProfile("key", common.ProfileExecutable)
	require.True(t, found, "the management application must still register executable commands")
	require.Error(t, apps.Management.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileManagement}}, "key", "generate"))
}

func TestSharedCommandsSelectExecutableOnlyInputsPerInvocation(t *testing.T) {
	apps := newTestApplications(t)

	for _, command := range [][]string{
		{"flow", "ls", "--help"},
		{"session", "ls", "--help"},
		{"audit", "events", "--help"},
		{"recording", "ls", "--help"},
	} {
		var executableOutput, managementOutput bytes.Buffer
		profile := &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}
		ctx := clibase.ContextWithStdio(t.Context(), nil, &executableOutput, nil)
		require.NoError(t, apps.Executable.ParseAndExecute(ctx, profile, command...))
		ctx = clibase.ContextWithStdio(t.Context(), nil, &managementOutput, nil)
		require.NoError(t, apps.Management.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileManagement}}, command...))
		require.Contains(t, executableOutput.String(), "--configuration")
		require.NotContains(t, managementOutput.String(), "--configuration")
	}

	ctx := clibase.ContextWithStdio(t.Context(), nil, &bytes.Buffer{}, nil)
	management := &clibase.ParseOpts{Profiles: []string{common.ProfileManagement}}
	require.Error(t, apps.Management.ParseAndExecute(ctx, management, "audit", "events", "default", "--limit=-1"))
	require.Error(t, apps.Management.ParseAndExecute(ctx, management, "audit", "events", "default", "--decryptionIdentityFile=private.key"))
	require.Error(t, apps.Management.ParseAndExecute(ctx, management, "flow", "ls", "--configuration=private.yaml"))
	require.Error(t, apps.Management.ParseAndExecute(ctx, management, "recording", "inspect", "recording.bcast"))
}

func TestEveryRegisteredCommandDeclaresItsProfiles(t *testing.T) {
	apps := newTestApplications(t)

	for _, app := range []clibase.Container{apps.Executable, apps.Management} {
		assertCommandProfiles(t, app)
	}
}

func TestBrowseCommandsHaveSeparateProfileVariants(t *testing.T) {
	apps := newTestApplications(t)

	for _, app := range []clibase.Container{apps.Executable, apps.Management} {
		for _, group := range []string{"audit", "flow", "session", "recording"} {
			parent, found := app.CommandOfProfile(group, common.ProfileManagement)
			require.True(t, found, "%s group is missing", group)
			for _, name := range []string{"ls", "show"} {
				executable, found := parent.CommandOfProfile(name, common.ProfileExecutable)
				require.True(t, found, "%s %s executable variant is missing", group, name)
				management, found := parent.CommandOfProfile(name, common.ProfileManagement)
				require.True(t, found, "%s %s management variant is missing", group, name)
				require.Equal(t, []string{common.ProfileExecutable}, executable.Profiles())
				require.Equal(t, []string{common.ProfileManagement}, management.Profiles())
			}
		}
	}
}

func assertCommandProfiles(t *testing.T, container clibase.Container) {
	t.Helper()
	for command := range container.Commands() {
		profiles := command.Profiles()
		require.NotEmpty(t, profiles, "command %q has no explicit profile", command.Name())
		for _, profile := range profiles {
			require.Contains(t, []string{common.ProfileExecutable, common.ProfileManagement}, profile)
		}
		assertCommandProfiles(t, command)
	}
}

func TestAuditEventFlagsBelongToManagementSchema(t *testing.T) {
	app := NewApplication[clibase.NoOptions](nil, "Bifröst SSH management.", nil).
		MustCreate()
	defer func() { require.NoError(t, app.Close()) }()
	var out bytes.Buffer
	ctx := clibase.ContextWithStdio(t.Context(), nil, &out, nil)
	require.NoError(t, app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileManagement}}, "audit", "events", "--help"))
	require.Contains(t, out.String(), "--with-sensitive")
	require.Contains(t, out.String(), "--since")
}

func TestManagementApplicationSeparatesConcurrentInvocations(t *testing.T) {
	app := NewApplication[clibase.NoOptions](nil, "Bifröst SSH management.", nil).
		MustCreate()
	defer func() { require.NoError(t, app.Close()) }()
	const count = 12
	results := make([]string, count)
	failures := make([]error, count)
	var group sync.WaitGroup
	for index := range results {
		group.Add(1)
		go func() {
			defer group.Done()
			conf := &configuration.Configuration{Flows: configuration.Flows{{
				Name:        configuration.FlowName("flow-" + string(rune('a'+index))),
				Environment: configuration.Environment{V: &configuration.EnvironmentManagement{}},
			}}}
			var output bytes.Buffer
			ctx := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{Configuration: conf})
			ctx = clibase.ContextWithStdio(ctx, nil, &output, nil)
			failures[index] = app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileManagement}}, "flow", "ls", "--format=json")
			results[index] = output.String()
		}()
	}
	group.Wait()
	for index := range results {
		require.NoError(t, failures[index])
		require.Contains(t, results[index], "flow-"+string(rune('a'+index)))
	}
}

func TestManagementApplicationDoesNotShareCredentialDisclosure(t *testing.T) {
	app := NewApplication[clibase.NoOptions](nil, "Bifröst SSH management.", nil).
		MustCreate()
	defer func() { require.NoError(t, app.Close()) }()
	const secret = "invocation-only-credential"
	conf := &configuration.Configuration{Flows: configuration.Flows{{
		Name: "production", Environment: configuration.Environment{
			V: &configuration.EnvironmentDocker{ImagePullCredentials: template.MustNewString(secret)},
		},
	}}}
	for _, disclose := range []bool{false, true, false} {
		var output bytes.Buffer
		ctx := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{
			Configuration: conf, IncludingCredentials: disclose,
		})
		ctx = clibase.ContextWithStdio(ctx, nil, &output, nil)
		require.NoError(t, app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileManagement}}, "flow", "show", "production", "--format=json"))
		if disclose {
			require.Contains(t, output.String(), secret)
		} else {
			require.NotContains(t, output.String(), secret)
		}
	}
}
