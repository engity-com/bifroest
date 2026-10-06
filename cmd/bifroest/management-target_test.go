package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseManagementTarget(t *testing.T) {
	for _, test := range []struct {
		name        string
		args        []string
		want        *managementTarget
		remainder   []string
		errContains string
	}{
		{"local", []string{"session", "ls"}, nil, []string{"session", "ls"}, ""},
		{"config alias", []string{"@my-bifroest", "session", "ls"}, &managementTarget{RawHost: "my-bifroest", Port: 22}, []string{"session", "ls"}, ""},
		{"explicit user and port", []string{"@admin@my.host:2222", "session", "ls"}, &managementTarget{User: "admin", RawHost: "my.host", Port: 2222, ExplicitPort: true}, []string{"session", "ls"}, ""},
		{"IPv6 literal", []string{"@admin@[::1]:2222", "session", "ls"}, &managementTarget{User: "admin", RawHost: "::1", Port: 2222, ExplicitPort: true}, []string{"session", "ls"}, ""},
		{"IPv6 default port", []string{"@[::1]", "session", "ls"}, &managementTarget{RawHost: "::1", Port: 22}, []string{"session", "ls"}, ""},
		{"missing target", []string{"@", "session", "ls"}, nil, nil, "required"},
		{"missing user", []string{"@@host", "session", "ls"}, nil, nil, "user"},
		{"missing host", []string{"@admin@", "session", "ls"}, nil, nil, "host"},
		{"invalid port", []string{"@host:bad", "session", "ls"}, nil, nil, "invalid"},
		{"invalid host", []string{"@-host", "session", "ls"}, nil, nil, "invalid"},
		{"not first", []string{"session", "@host", "ls"}, nil, nil, "first argument"},
		{"remote with second target", []string{"@admin", "session", "@other", "ls"}, nil, nil, "first argument"},
		{"non-management response file", []string{"version", "@local-args"}, nil, []string{"version", "@local-args"}, ""},
		{"non-management command with target-shaped argument", []string{"run", "@host"}, nil, []string{"run", "@host"}, ""},
		{"management response file", []string{"flow", "ls", "@local-args"}, nil, nil, "first argument"},
		{"logging flag before management", []string{"--log.level=INFO", "flow", "ls", "@local-args"}, nil, nil, "first argument"},
		{"separate logging value before management", []string{"--log.level", "INFO", "session", "ls", "@local-args"}, nil, nil, "first argument"},
		{"logging value named flow", []string{"--log.level", "flow", "version", "@local-args"}, nil, []string{"--log.level", "flow", "version", "@local-args"}, ""},
		{"logging flag before non-management", []string{"--log.level=INFO", "version", "@local-args"}, nil, []string{"--log.level=INFO", "version", "@local-args"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual, args, err := parseManagementTarget(test.args)
			if test.errContains != "" {
				require.ErrorContains(t, err, test.errContains)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, actual)
			require.Equal(t, test.remainder, args)
		})
	}
	require.False(t, supportsRemoteManagementCommand("run"))
	require.True(t, supportsRemoteManagementCommand("session ls"))
}
