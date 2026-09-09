package sys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnvVarsSetCanonicalRemovesCaseAliases(t *testing.T) {
	environment := EnvVars{
		"bifroest_execution_id": "attacker",
		"BiFrOeSt_ExEcUtIoN_Id": "also-attacker",
		"UNCHANGED":             "value",
	}

	environment.SetCanonical("BIFROEST_EXECUTION_ID", "trusted")

	require.Equal(t, EnvVars{
		"BIFROEST_EXECUTION_ID": "trusted",
		"UNCHANGED":             "value",
	}, environment)
}
