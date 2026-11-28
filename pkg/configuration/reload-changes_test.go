package configuration

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReloadChangesPropagateEffectiveRootDefinitions(t *testing.T) {
	before := snapshotTestLoad(t, snapshotTestSource)
	for _, test := range []struct {
		name          string
		old, next     string
		authorization bool
		environment   bool
	}{
		{"authorization", "original-password", "new-password", true, false},
		{"environment", "original-environment", "new-environment", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			after := snapshotTestLoad(t, strings.Replace(snapshotTestSource, test.old, test.next, 1))
			changes := before.ChangesTo(after)
			require.True(t, changes.Changed)
			require.True(t, changes.RuntimeChanged())
			require.Equal(t, []FlowReloadChange{
				{Name: "first", Authorization: test.authorization, Environment: test.environment},
				{Name: "second", Authorization: test.authorization, Environment: test.environment},
			}, changes.ModifiedFlows)
			require.Empty(t, changes.Sections)
			require.Empty(t, changes.AddedFlows)
			require.Empty(t, changes.RemovedFlows)
			require.False(t, changes.FlowOrderChanged)
			require.NotContains(t, fmt.Sprintf("%+v", changes), test.old)
			require.NotContains(t, fmt.Sprintf("%+v", changes), test.next)
		})
	}
	require.Equal(t, "original-environment", before.Configuration().Flows[0].Environment.V.(*EnvironmentDummy).Banner.String())
}

func TestReloadChangesIgnoreUnusedDefinitionsAndEquivalentReferencesAtRuntime(t *testing.T) {
	for _, test := range []struct {
		name   string
		before string
		after  string
	}{
		{
			"unused root environment",
			snapshotTestSource,
			strings.Replace(snapshotTestSource, "unused-environment", "different-unused-environment", 1),
		},
		{
			"equivalent named reference",
			"environments:\n  one: {type: dummy}\n  two: {type: dummy}\nflows:\n  - name: first\n    environment: one\n    authorization: {type: none}\n",
			"environments:\n  one: {type: dummy}\n  two: {type: dummy}\nflows:\n  - name: first\n    environment: two\n    authorization: {type: none}\n",
		},
		{
			"equivalent default and inline",
			referenceTestDefaults + "flows:\n  - name: first\n",
			referenceTestDefaults + "flows:\n  - name: first\n    authorization: {type: none}\n    environment: {type: dummy, banner: root-environment}\n",
		},
		{
			"equivalent authorization reference",
			"authorizations:\n  one: {type: none}\n  two: {type: none}\nflows:\n  - name: first\n    environment: {type: dummy}\n    authorization: one\n",
			"authorizations:\n  one: {type: none}\n  two: {type: none}\nflows:\n  - name: first\n    environment: {type: dummy}\n    authorization: two\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := snapshotTestLoad(t, test.before)
			after := snapshotTestLoad(t, test.after)
			changes := before.ChangesTo(after)
			require.True(t, changes.Changed, "accepted source declarations still need updating")
			require.False(t, changes.RuntimeChanged())
		})
	}
}

func TestReloadChangesIgnoreFormattingAndSourceFilename(t *testing.T) {
	before := snapshotTestLoad(t, referenceTestInlineFlow)
	after := snapshotTestLoad(t, "# same configuration\nflows:\n  - authorization: { type: none }\n    environment: { type: dummy }\n    name: inline\n")
	after.configuration.Filename = "a-different-source.yaml"
	require.Equal(t, ReloadChanges{}, before.ChangesTo(after))
}

func TestReloadChangesDistinguishDeletionRenameAndOrder(t *testing.T) {
	before := snapshotTestLoad(t, snapshotTestSource)
	renamed := strings.Replace(snapshotTestSource, "name: first", "name: replacement", 1)
	changes := before.ChangesTo(snapshotTestLoad(t, renamed))
	require.Equal(t, []FlowName{"first"}, changes.RemovedFlows)
	require.Equal(t, []FlowName{"replacement"}, changes.AddedFlows)
	require.Empty(t, changes.ModifiedFlows)
	require.False(t, changes.FlowOrderChanged)

	conf := before.Configuration()
	slices.Reverse(conf.Flows)
	after, err := NewSnapshot(conf)
	require.NoError(t, err)
	changes = before.ChangesTo(after)
	require.True(t, changes.FlowOrderChanged)
	require.True(t, changes.RuntimeChanged())
	require.Empty(t, changes.ModifiedFlows)
	require.Empty(t, changes.AddedFlows)
	require.Empty(t, changes.RemovedFlows)
}

func TestReloadChangesSeparatePolicyAndReferencedAuditlog(t *testing.T) {
	beforeSource := "auditlogs:\n  shared: {minimumFreeBytes: 1}\n" +
		strings.Replace(snapshotTestSource, "name: first,", "name: first, auditlog: shared,", 1)
	before := snapshotTestLoad(t, beforeSource)
	afterSource := strings.Replace(beforeSource, "minimumFreeBytes: 1", "minimumFreeBytes: 2", 1)
	afterSource = strings.Replace(afterSource, "name: second,", "name: second, title: Changed,", 1)
	changes := before.ChangesTo(snapshotTestLoad(t, afterSource))
	require.Equal(t, []string{"auditlogs"}, changes.Sections)
	require.Equal(t, []FlowReloadChange{
		{Name: "first", Auditlog: true},
		{Name: "second", Policy: true},
	}, changes.ModifiedFlows)
}

func TestReloadChangesClassifyProcessSettings(t *testing.T) {
	for _, test := range []struct{ section, source string }{
		{"ssh", "ssh: {banner: changed}\n"},
		{"http", "http: {maxHeaderBytes: 2048}\n"},
		{"monitoring", "monitoring: {maxHeaderBytes: 2048}\n"},
		{"tls", "tls: {unused: {dummy: true}}\n"},
		{"session", "session: {type: fs, storage: other-sessions}\n"},
		{"housekeeping", "housekeeping: {every: 1m}\n"},
		{"alternatives", "alternatives: {location: other-alternatives}\n"},
		{"startMessage", "startMessage: changed\n"},
		{"auditlogs", "auditlogs: {unused: {}}\n"},
	} {
		t.Run(test.section, func(t *testing.T) {
			before := snapshotTestLoad(t, referenceTestInlineFlow)
			after := snapshotTestLoad(t, test.source+referenceTestInlineFlow)
			changes := before.ChangesTo(after)
			require.True(t, changes.Changed)
			require.True(t, changes.RuntimeChanged())
			require.Equal(t, []string{test.section}, changes.Sections)
			require.Empty(t, changes.ModifiedFlows)
		})
	}
}

func TestReloadChangesCoverRootConfigurationSchema(t *testing.T) {
	// A new root field must get an explicit classification; never silently
	// accept an unsupported future setting merely because it was not compared.
	var fields []string
	typ := reflect.TypeFor[Configuration]()
	for index := range typ.NumField() {
		fields = append(fields, typ.Field(index).Name)
	}
	require.ElementsMatch(t, []string{
		"Environments", "Authorizations", "Auditlogs", "Ssh", "Http", "Monitoring",
		"Session", "Flows", "HouseKeeping", "Alternatives", "StartMessage", "Filename", "Tls",
	}, fields)
}
