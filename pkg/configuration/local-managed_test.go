//go:build unix || windows

package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalManagedGroupSelectionPreservesCapabilityAndFlowOrder(t *testing.T) {
	local := func(group string) Environment {
		return Environment{V: &EnvironmentLocal{EnvironmentLocalCommon: EnvironmentLocalCommon{ManagedGroup: group}}}
	}
	for _, test := range []struct {
		label     string
		flows     Flows
		name      FlowName
		group     string
		available bool
	}{
		{"no flows", nil, "flow", "", false},
		{"other flow", Flows{{Name: "other", Environment: local("managed")}}, "flow", "", false},
		{"no environment", Flows{{Name: "flow"}}, "flow", "", false},
		{"non-local environment", Flows{{Name: "flow", Environment: Environment{V: &EnvironmentSsh{}}}}, "flow", "", false},
		{"typed nil local environment", Flows{{Name: "flow", Environment: Environment{V: (*EnvironmentLocal)(nil)}}}, "flow", "", false},
		{"no management selector", Flows{{Name: "flow", Environment: local("")}}, "flow", "", false},
		{"configured selector", Flows{{Name: "other", Environment: local("other")}, {Name: "flow", Environment: local("Managed")}}, "flow", "Managed", true},
		{"first matching flow remains authoritative", Flows{{Name: "flow"}, {Name: "flow", Environment: local("managed")}}, "flow", "", false},
	} {
		t.Run(test.label, func(t *testing.T) {
			group, available := test.flows.LocalManagedGroupFor(test.name)
			require.Equal(t, test.group, group)
			require.Equal(t, test.available, available)
		})
	}
}
