package policy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/management/protocol"
)

func TestForcedActionAllowsOnlyExactActionAndCanonicalID(t *testing.T) {
	id := "9c77b24c-62f4-44c2-aea3-771c75e5a107"
	for _, action := range []string{"disconnect", "dispose"} {
		for _, suffix := range []string{"", " --format=json", " --format yaml", " --format=cbor", " --format='table'"} {
			ceiling, err := ForcedAction("session " + action + " " + id + suffix)
			require.NoError(t, err)
			require.True(t, ceiling.Allows(protocol.SessionAction{Action: action, Flow: "worker", ID: id}))
			require.False(t, ceiling.Allows(protocol.SessionAction{Action: action, Flow: "worker", ID: "00000000-0000-0000-0000-000000000001"}))
			for _, other := range []string{"disconnect", "dispose", "show", "ls"} {
				require.Equal(t, other == action, ceiling.Allows(protocol.SessionAction{Action: other, Flow: "worker", ID: id}))
			}
			_, err = ForcedRead("session " + action + " " + id + suffix)
			require.Error(t, err, "an action must not imply a read capability")
		}
	}
	for _, raw := range []string{
		"", "session", "session dispose", "session dispose bad", "session dispose " + strings.ToUpper(id),
		"session dispose " + id + " " + id, "session show " + id, "session ls", "flow ls",
		"session dispose " + id + " --flow=worker", "session dispose " + id + " --user=bob",
		"session dispose " + id + " --configuration=private", "session dispose " + id + " --format=json --format=yaml",
		"session dispose " + id + " --format=@private", "session dispose " + id + " --format=internal-cbor",
		"session dispose " + id + " --format=JSON", "session dispose " + id + " --format",
		"session dispose " + id + " #comment", "session dispose " + id + " && flow ls",
		"session dispose " + id + ";", "session dispose " + id + "\x00", "sh -c 'session dispose " + id + "'",
		"_bifroest-management-v1", "session delete " + id, strings.Repeat("x", 16<<10+1), "session dispose \xff",
	} {
		_, err := ForcedAction(raw)
		require.Error(t, err, raw)
	}
}
