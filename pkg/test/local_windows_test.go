//go:build windows

package test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const localWindowsConfiguration = `flows:
 - name: primary
   authorization:
     type: local
     remoteName: ALICE
     principal: 'mapped-{{ .authentication.principal }}'
   environment:
     type: local
     name: '{{ .authentication.principal }}'
     managedGroup: managed
     shellCommand: [C:/fixture/cmd.exe]
     execCommandPrefix: []
     directory: '{{ .authorization.user.homeDir }}/work'
     groups: [{name: application, gid: S-1-5-21-1-2-3-4001}]
     portForwardingAllowed: '{{ .authorization.user.managed }}'
`

func localWindowsSource(groups, verify string) string {
	return `suite{name="local-windows",
 environment=object{` + groups + `,accounts=list{
 object{name="alice",sid="S-1-5-21-1-2-3-1001",homeDir="C:/fixture/alice"},
 object{name="mapped-alice",sid="S-1-5-21-1-2-3-2001"}}},
 tests={{name="selected",input=object{request=object{requestingName="ops"},authentication=object{primary=object{outcome="allow",mode="mapped-local"}}},verify=function(t,actual)` + verify + ` end}}}`
}

func TestLocalWindowsSelectionUsesModeledSIDMembershipAndSeparateTarget(t *testing.T) {
	source := localWindowsSource(`localGroups=list{object{name="MANAGED",sid="S-1-5-21-1-2-3-3001",members=list{"S-1-5-21-1-2-3-1001"}}}`, `
 t:IsEqual("selected",actual.decision)
 t:IsEqual("ALICE",actual.authentication.remoteName)
 t:IsEqual("alice",actual.authentication.account)
 t:IsEqual("mapped-alice",actual.identity.principal)
 t:IsEqual("local-windows",actual.environment.kind)
 t:IsEqual("mapped-alice",actual.environment.name)
 t:IsEqual("",actual.environment.requestedSID)
 t:IsEqual("C:/fixture/alice/work",actual.environment.directory)
 t:IsEqual(true,actual.environment.portForwardingAllowed)
 t:IsEqual(list{"C:/fixture/cmd.exe"},actual.environment.shellCommand)
 t:IsEqual(list{},actual.environment.execCommandPrefix)
 t:IsEqual("application",actual.environment.groups[1].name)
 t:IsEqual("S-1-5-21-1-2-3-4001",actual.environment.groups[1].gid)
 `)
	report := RunSources(t.Context(), []byte(source), []byte(localWindowsConfiguration))
	require.Zero(t, report.ExitCode(), "%+v", report)
}

func TestLocalWindowsUnknownMembershipIsNotFalse(t *testing.T) {
	for _, test := range []struct {
		facts string
		code  int
	}{
		{`localGroups=list{}`, 2},
		{`localGroups=list{object{name="managed",sid="S-1-5-21-1-2-3-3001"}}`, 2},
		{`localGroups=list{object{name="managed",sid="S-1-5-21-1-2-3-3001",members=list{}}}`, 0},
		{`localGroups=list{object{name="managed",sid="S-1-5-21-1-2-3-3001",members=list{"S-1-5-21-1-2-3-9999"}}}`, 0},
		{`absentGroupNames=list{"managed"}`, 0},
	} {
		source := localWindowsSource(test.facts, `t:IsEqual(false,actual.environment.portForwardingAllowed)`)
		report := RunSources(t.Context(), []byte(source), []byte(localWindowsConfiguration))
		require.Equal(t, test.code, report.ExitCode(), "%+v", report)
	}
}

func TestLocalWindowsHostShellDefaultsRequireExplicitConfiguration(t *testing.T) {
	source := localWindowsSource(`absentGroupNames=list{"managed"}`, `t:IsEqual(false,actual.environment.portForwardingAllowed)`)
	for _, line := range []string{"     shellCommand: [C:/fixture/cmd.exe]\n", "     execCommandPrefix: []\n"} {
		configuration := strings.Replace(localWindowsConfiguration, line, "", 1)
		report := RunSources(t.Context(), []byte(source), []byte(configuration))
		require.Equal(t, 2, report.ExitCode(), "%+v", report)
		require.Zero(t, report.Results[0].Assertions)
	}
	configuration := strings.Replace(localWindowsConfiguration, "shellCommand: [C:/fixture/cmd.exe]", "shellCommand: []", 1)
	source = localWindowsSource(`absentGroupNames=list{"managed"}`, `t:IsEqual(list{},actual.environment.shellCommand);t:IsEqual(list{},actual.environment.execCommandPrefix)`)
	require.Zero(t, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
}

func TestLocalWindowsHostShellAdmissionUsesProductionTypeMatching(t *testing.T) {
	prefix, environment, found := strings.Cut(localWindowsConfiguration, "   environment:\n")
	require.True(t, found)
	for _, named := range []bool{false, true} {
		for _, kind := range []string{"local", "LOCAL", "Local", "lOcAl"} {
			body := strings.Replace(environment, "type: local", "type: "+kind, 1)
			configuration := prefix + "   environment:\n" + body
			name := "inline/" + kind
			if named {
				configuration = "environments:\n target:\n" + body + prefix + "   environment: target\n"
				name = "named/" + kind
			}
			t.Run(name, func(t *testing.T) {
				for _, test := range []struct {
					name, shell, exec string
					code              int
				}{
					{"explicit empty", "[]", "[]", 0},
					{"missing shell", "", "[]", 2},
					{"missing prefix", "[C:/fixture/cmd.exe]", "", 2},
					{"missing both", "", "", 2},
					{"null shell", "null", "[]", 2},
					{"null prefix", "[C:/fixture/cmd.exe]", "null", 2},
				} {
					t.Run(test.name, func(t *testing.T) {
						conf := configuration
						for _, field := range []struct{ name, old, value string }{
							{"shellCommand", "[C:/fixture/cmd.exe]", test.shell},
							{"execCommandPrefix", "[]", test.exec},
						} {
							line := "     " + field.name + ": " + field.old + "\n"
							replacement := ""
							if field.value != "" {
								replacement = "     " + field.name + ": " + field.value + "\n"
							}
							require.Contains(t, conf, line)
							conf = strings.Replace(conf, line, replacement, 1)
						}
						source := localWindowsSource(`absentGroupNames=list{"managed"}`, `t:IsEqual(list{},actual.environment.shellCommand);t:IsEqual(list{},actual.environment.execCommandPrefix)`)
						report := RunSources(t.Context(), []byte(source), []byte(conf))
						require.Equal(t, test.code, report.ExitCode(), "%+v", report)
						require.Len(t, report.Results, 1)
						if test.code == 2 {
							require.Equal(t, "config", report.Results[0].Category)
							require.Zero(t, report.Results[0].Assertions)
						} else {
							require.Equal(t, Summary{Passed: 1}, report.Summary())
							require.Equal(t, 2, report.Results[0].Assertions)
						}
					})
				}
			})
		}
	}
}

func TestLocalWindowsSelectedSIDMustAgreeWithTheName(t *testing.T) {
	source := localWindowsSource(`absentGroupNames=list{"managed"}`, `t:IsEqual(true,true)`)
	configuration := strings.Replace(localWindowsConfiguration, "managedGroup: managed", "uid: S-1-5-21-1-2-3-2001\n     managedGroup: managed", 1)
	require.Zero(t, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
	configuration = strings.Replace(configuration, "uid: S-1-5-21-1-2-3-2001", "uid: S-1-5-21-1-2-3-1001", 1)
	require.Equal(t, 2, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
}

func TestLocalWindowsAbsentAndUnmodeledTargetsRemainDistinct(t *testing.T) {
	source := localWindowsSource(`absentGroupNames=list{"managed"}`, `t:IsEqual("absent-target",actual.environment.name)`)
	configuration := strings.Replace(localWindowsConfiguration, "name: '{{ .authentication.principal }}'", "name: absent-target", 1)
	require.Equal(t, 2, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
	source = strings.Replace(source, "environment=object{", `environment=object{absentNames=list{"absent-target"},`, 1)
	require.Zero(t, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
}

func TestLocalWindowsLoginAdmissionPrecedesTargetLookup(t *testing.T) {
	source := localWindowsSource(`localGroups=list{}`, `t:IsEqual("deny",actual.decision);t:IsEqual("local-login",actual.stage)`)
	configuration := strings.Replace(localWindowsConfiguration, "name: '{{ .authentication.principal }}'", "name: unmodeled-target\n     loginAllowed: false", 1)
	require.Zero(t, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
}
