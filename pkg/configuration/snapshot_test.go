package configuration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/template"
)

const snapshotTestSource = `ssh: {enabled: true}
environments:
  shared: {type: dummy, banner: original-environment}
  unused: {type: dummy, banner: unused-environment}
authorizations:
  shared:
    type: simple
    entries:
      - {name: alice, password: "plain:original-password"}
flows:
  - {name: first, environment: shared, authorization: shared}
  - {name: second, environment: shared, authorization: shared}
  - name: independent
    environment: {type: dummy}
    authorization: {type: none}
`

func snapshotTestConfiguration(t *testing.T, source string) Configuration {
	t.Helper()
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(source), ""))
	return conf
}

func snapshotTestLoad(t *testing.T, source string) *Snapshot {
	t.Helper()
	result, err := NewSnapshot(snapshotTestConfiguration(t, source))
	require.NoError(t, err)
	return result
}

func TestSnapshotOwnsConfigurationAndReturnedCopies(t *testing.T) {
	initial := snapshotTestConfiguration(t, snapshotTestSource)
	snapshot, err := NewSnapshot(initial)
	require.NoError(t, err)
	want := snapshot.Configuration()

	mutate := func(conf Configuration) {
		*conf.Ssh.Enabled = false
		conf.Ssh.Addresses[0] = net.MustNewAddress("127.0.0.1:2222")
		conf.Environments["shared"].V.(*EnvironmentDummy).Banner = template.MustNewString("changed-root")
		conf.Flows[0].Environment.V.(*EnvironmentDummy).Banner = template.MustNewString("changed-flow")
		conf.Authorizations["shared"].V.(*AuthorizationSimple).Entries[0].Name = "changed-root-user"
		conf.Flows[0].Authorization.V.(*AuthorizationSimple).Entries[0].Name = "changed-flow-user"
		delete(conf.Environments, "unused")
		conf.Flows[0].Name = "renamed"
	}
	mutate(initial)
	mutate(snapshot.Configuration())

	require.True(t, want.IsEqualTo(snapshot.Configuration()), "neither the caller nor a returned copy may mutate a snapshot")
	require.NotSame(t, snapshot.configuration.Flows[0].Environment.V, snapshot.configuration.Flows[1].Environment.V)
}

func TestSnapshotRejectsInvalidReferencesWithoutMutatingInput(t *testing.T) {
	initial := snapshotTestConfiguration(t, snapshotTestSource)
	initial.Flows[0].Environment.Reference = "missing"
	provider := initial.Flows[0].Environment.V
	snapshot, err := NewSnapshot(initial)
	require.ErrorContains(t, err, `references unknown environment "missing"`)
	require.Nil(t, snapshot)
	require.Same(t, provider, initial.Flows[0].Environment.V)
	require.Equal(t, "original-environment", provider.(*EnvironmentDummy).Banner.String())
}

func TestSnapshotPreservesValidProgrammaticZeroRecording(t *testing.T) {
	conf := snapshotTestConfiguration(t, referenceTestInlineFlow)
	conf.Auditlogs = append(conf.Auditlogs, Auditlog{
		Name: "unused", IdentityFile: "identity", Directory: "journal",
	})
	require.NoError(t, conf.Validate())
	snapshot, err := NewSnapshot(conf)
	require.NoError(t, err)
	require.True(t, snapshot.Configuration().IsEqualTo(conf))
	require.True(t, snapshot.Configuration().Auditlogs[0].Recording.IsZero())
}

func TestSnapshotAndYamlValidationDoNotCreatePasswordFiles(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint(invalid), func(t *testing.T) {
			passwordFile := filepath.Join(t.TempDir(), "must-not-be-created")
			source := fmt.Sprintf(`flows:
  - name: first
    authorization:
      type: simple
      entries:
        - name: alice
          passwordFile: %q
          createPasswordFileIfAbsentOfType: plain
    environment: {type: dummy}
`, filepath.ToSlash(passwordFile))
			if invalid {
				source += "  - name: invalid\n    authorization: {type: none}\n"
			}
			var conf Configuration
			err := conf.LoadFromYaml(strings.NewReader(source), "")
			if invalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				_, err = NewSnapshot(conf)
				require.NoError(t, err)
			}
			_, err = os.Stat(passwordFile)
			require.True(t, os.IsNotExist(err), "loading or validating a candidate must not provision credentials")
		})
	}
}

func TestConfigurationRejectsTrailingYamlDocumentsWithoutReplacingCurrent(t *testing.T) {
	for _, trailing := range []string{
		referenceTestInlineFlow,
		"flows: [",
		"",
	} {
		t.Run(fmt.Sprintf("%q", trailing), func(t *testing.T) {
			current := snapshotTestConfiguration(t, snapshotTestSource)
			before, err := NewSnapshot(current)
			require.NoError(t, err)
			err = current.LoadFromYaml(strings.NewReader(referenceTestInlineFlow+"\n---\n"+trailing), "")
			require.Error(t, err)
			require.True(t, before.Configuration().IsEqualTo(current))
		})
	}
	var current Configuration
	require.NoError(t, current.LoadFromYaml(strings.NewReader(referenceTestInlineFlow+"\n# trailing comments are allowed\n"), ""))
}
