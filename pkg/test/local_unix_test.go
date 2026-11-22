//go:build unix

package test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const localUnixConfiguration = `flows:
 - name: primary
   authorization:
     type: local
     remoteName: alice
     principal: 'mapped-{{ .authentication.principal }}'
   environment:
     type: local
     name: '{{ .authentication.principal }}'
     managedGroup: managed
     shellCommand: [/fixture/sh]
     execCommandPrefix: [/fixture/env]
     directory: '{{ .authorization.user.homeDir }}/work'
     portForwardingAllowed: '{{ .authorization.user.managed }}'
`

func localUnixSource(group, targets, verify string) string {
	return `suite{name="local-unix",
 environment=object{accounts=list{object{name="alice",uid=1001,homeDir="/fixture/alice",` + group + `}` + targets + `}},
 tests={{name="selected",input=object{request=object{requestingName="ops"},authentication=object{primary=object{outcome="allow",mode="mapped-local"}}},verify=function(t,actual)` + verify + ` end}}}`
}

func TestLocalUnixSelectionKeepsAuthenticationAndTargetSeparate(t *testing.T) {
	source := localUnixSource(`group=object{name="managed",gid=200}`, `,object{name="mapped-alice",uid=2001}`, `
 t:IsEqual("selected",actual.decision)
 t:IsEqual("alice",actual.authentication.account)
 t:IsEqual("mapped-alice",actual.identity.principal)
 t:IsEqual("local",actual.environment.type)
 t:IsEqual("local-unix",actual.environment.kind)
 t:IsEqual("mapped-alice",actual.environment.account.name)
 t:IsEqual(null,actual.environment.account.uid)
 t:IsEqual(list{"/fixture/sh"},actual.environment.shellCommand)
 t:IsEqual(list{"/fixture/env"},actual.environment.execCommandPrefix)
 t:IsEqual("/fixture/alice/work",actual.environment.directory)
 t:IsEqual(true,actual.environment.portForwardingAllowed)
 `)
	report := RunSources(t.Context(), []byte(source), []byte(localUnixConfiguration))
	require.Zero(t, report.ExitCode(), "%+v", report)
}

func TestLocalUnixManagedUsesPrimaryThenSupplementaryNames(t *testing.T) {
	for _, test := range []struct {
		facts string
		want  string
		code  int
	}{
		{`group=object{name="managed",gid=200}`, "true", 0},
		{`group=object{name="users",gid=200},groups=list{object{name="managed",gid=201}}`, "true", 0},
		{`group=object{name="users",gid=200},groups=list{}`, "false", 0},
		{`group=object{name="MANAGED",gid=200},groups=list{}`, "false", 0},
		{`group=object{name="users",gid=200}`, "false", 2},
		{`groups=list{object{name="managed",gid=201}}`, "true", 2},
	} {
		source := localUnixSource(test.facts, `,object{name="mapped-alice",uid=2001}`, `t:IsEqual(`+test.want+`,actual.environment.portForwardingAllowed)`)
		report := RunSources(t.Context(), []byte(source), []byte(localUnixConfiguration))
		require.Equal(t, test.code, report.ExitCode(), "%+v", report)
	}
}

func TestLocalUnixTargetsDistinguishExplicitAbsenceAndUnknown(t *testing.T) {
	source := localUnixSource(`group=object{name="managed",gid=200}`, "", `t:IsEqual("mapped-alice",actual.environment.account.name)`)
	require.Equal(t, 2, RunSources(t.Context(), []byte(source), []byte(localUnixConfiguration)).ExitCode())
	source = strings.Replace(source, "environment=object{", `environment=object{absentNames=list{"mapped-alice"},`, 1)
	require.Zero(t, RunSources(t.Context(), []byte(source), []byte(localUnixConfiguration)).ExitCode())
}

func TestLocalUnixZeroUIDAndNamePrecedenceUseProductionSelectors(t *testing.T) {
	source := localUnixSource(`group=object{name="managed",gid=200}`, `,object{name="target-zero",uid=0}`, `t:IsEqual(0,actual.environment.account.uid);t:IsEqual("target-zero",actual.environment.account.name)`)
	configuration := strings.Replace(localUnixConfiguration, "name: '{{ .authentication.principal }}'", "uid: 0", 1)
	require.Zero(t, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
	source = localUnixSource(`group=object{name="managed",gid=200}`, `,object{name="mapped-alice",uid=2001}`, `t:IsEqual(0,actual.environment.account.uid);t:IsEqual("mapped-alice",actual.environment.account.name)`)
	configuration = strings.Replace(localUnixConfiguration, "name: '{{ .authentication.principal }}'", "name: '{{ .authentication.principal }}'\n     uid: 0", 1)
	require.Zero(t, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
}

func TestLocalUnixSelectorAdmissionRejectsHostFunctionsEverywhere(t *testing.T) {
	source := localUnixSource(`group=object{name="managed",gid=200}`, `,object{name="mapped-alice",uid=2001}`, `t:IsEqual(true,true)`)
	for _, replacement := range []string{
		"name: '{{ env \"BIFROEST_TEST_ACCOUNT\" }}'",
		"shell: '{{ file \"/not-an-allowed-host-file\" }}'",
		"homeDir: '{{ range .authorization.user.groups }}x{{ end }}'",
		"groups: [{name: '{{ env \"BIFROEST_TEST_GROUP\" }}'}]",
		"shellCommand: ['{{ env \"BIFROEST_TEST_SHELL\" }}']",
		"execCommandPrefix: ['{{ env \"BIFROEST_TEST_PREFIX\" }}']",
	} {
		configuration := strings.Replace(localUnixConfiguration, "managedGroup: managed", "managedGroup: managed\n     "+replacement, 1)
		for _, existing := range []string{"name: '{{ .authentication.principal }}'", "shellCommand: [/fixture/sh]", "execCommandPrefix: [/fixture/env]"} {
			if strings.HasPrefix(replacement, strings.SplitN(existing, ":", 2)[0]+":") {
				configuration = strings.Replace(localUnixConfiguration, existing, replacement, 1)
			}
		}
		report := RunSources(t.Context(), []byte(source), []byte(configuration))
		require.Equal(t, 2, report.ExitCode(), "%s: %+v", replacement, report)
	}
}

func TestLocalUnixMetadataAndRuntimeContextsAreNotInvented(t *testing.T) {
	source := localUnixSource(`group=object{name="managed",gid=200}`, `,object{name="mapped-alice",uid=2001}`, `t:IsEqual(true,true)`)
	missingHome := strings.Replace(source, `homeDir="/fixture/alice",`, "", 1)
	require.Equal(t, 2, RunSources(t.Context(), []byte(missingHome), []byte(localUnixConfiguration)).ExitCode())
	configuration := strings.Replace(localUnixConfiguration, `{{ .authorization.user.homeDir }}/work`, `{{ .user.homeDir }}`, 1)
	require.Equal(t, 2, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
}

func TestLocalUnixLoginAdmissionUsesProductionGateBeforeTargetSelection(t *testing.T) {
	source := localUnixSource(`group=object{name="managed",gid=200}`, "", `t:IsEqual("deny",actual.decision);t:IsEqual("local-login",actual.stage)`)
	configuration := strings.Replace(localUnixConfiguration, "managedGroup: managed", "managedGroup: managed\n     loginAllowed: false", 1)
	// The target is deliberately unmodeled and its selector is not admitted: the
	// productive denial must occur first, without target lookups or rendering.
	configuration = strings.Replace(configuration, "name: '{{ .authentication.principal }}'", `name: '{{ env "BIFROEST_TEST_MUST_NOT_RENDER" }}'`, 1)
	require.Zero(t, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
	configuration = strings.Replace(localUnixConfiguration, "managedGroup: managed", "managedGroup: managed\n     loginAllowed: '{{ .authorization.user.managed }}'", 1)
	source = localUnixSource(`group=object{name="users",gid=200},groups=list{}`, "", `t:IsEqual("deny",actual.decision);t:IsEqual("local-login",actual.stage)`)
	require.Zero(t, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
	source = localUnixSource(`group=object{name="users",gid=200}`, "", `t:IsEqual("deny",actual.decision)`)
	require.Equal(t, 2, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
}
