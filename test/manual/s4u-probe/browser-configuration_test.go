package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

func TestRememberBrowserConfigurationHasStrictGroupGatedLogin(t *testing.T) {
	const groupSID = "S-1-5-21-1-2-3-1002"
	for _, scenario := range []string{"key-only", "password-group", "missing-group"} {
		t.Run(scenario, func(t *testing.T) {
			password := scenario != "key-only"
			var text string
			switch scenario {
			case "key-only":
				text = browserConfiguration(`C:\owned`, `alice`, `S-1-5-21-1-2-3-1001`)
			case "password-group":
				text = browserConfigurationWithPassword(`C:\owned`, `alice`, `S-1-5-21-1-2-3-1001`, true, groupSID)
			default:
				text = browserConfigurationWithPassword(`C:\owned`, `alice`, `S-1-5-21-1-2-3-1001`, password)
			}
			var document map[string]any
			require.NoError(t, yaml.Unmarshal([]byte(text), &document))
			flow := document["flows"].([]any)[0].(map[string]any)
			method := flow["authorization"].(map[string]any)["password"].(map[string]any)
			require.Equal(t, password, method["allowed"])
			require.Equal(t, password, method["interactiveAllowed"])
			permission := template.MustNewBool(flow["environment"].(map[string]any)["loginAllowed"].(string))
			for _, member := range []bool{false, true} {
				gids := []string{}
				if member {
					gids = append(gids, groupSID)
				}
				allowed, err := permission.Render(map[string]any{"authorization": map[string]any{"user": map[string]any{"gids": gids}}})
				require.NoError(t, err)
				require.Equal(t, scenario == "key-only" || scenario == "password-group" && member, allowed)
			}
		})
	}
}
