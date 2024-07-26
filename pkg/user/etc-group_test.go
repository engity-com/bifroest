//go:build unix

package user

import (
	"github.com/echocat/slf4g/sdk/testlog"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_etcGroupEntry_decode(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name         string
		given        [][]byte
		allowBadName bool
		expected     etcGroupEntry
		expectedErr  string
	}{{
		name:         "simple",
		given:        bs("root", "x", "0", ""),
		allowBadName: false,
		expected:     etcGroupEntry{b("root"), b("x"), 0, nil},
	}, {
		name:         "forbidden-bad-group-name",
		given:        bs("root@", "x", "0", ""),
		allowBadName: false,
		expectedErr:  "illegal group name",
	}, {
		name:         "allowed-bad-group-name",
		given:        bs("root@", "x", "0", ""),
		allowBadName: true,
		expected:     etcGroupEntry{b("root@"), b("x"), 0, nil},
	}, {
		name:         "empty-group-name",
		given:        bs("", "x", "0", ""),
		allowBadName: false,
		expectedErr:  "empty group name",
	}, {
		name:         "illegal-group-name",
		given:        bs("ro\tot", "x", "0", ""),
		allowBadName: true,
		expectedErr:  "illegal group name",
	}, {
		name:         "too-long-group-name",
		given:        bs("a012345678901234567890123456789012", "x", "0", ""),
		allowBadName: true,
		expectedErr:  "group name is longer than 32 characters",
	}, {
		name:         "empty-gid",
		given:        bs("root", "x", "", ""),
		allowBadName: true,
		expectedErr:  "empty GID",
	}, {
		name:         "illegal-gid",
		given:        bs("root", "x", "-0", ""),
		allowBadName: true,
		expectedErr:  "illegal GID",
	}, {
		name:         "one-user-name",
		given:        bs("root", "x", "666", "one"),
		allowBadName: false,
		expected:     etcGroupEntry{b("root"), b("x"), 666, bs("one")},
	}, {
		name:         "two-user-names",
		given:        bs("root", "x", "123", "one,two"),
		allowBadName: false,
		expected:     etcGroupEntry{b("root"), b("x"), 123, bs("one", "two")},
	}, {
		name:         "empty-user-name",
		given:        bs("root", "x", "0", ",two"),
		allowBadName: false,
		expectedErr:  "empty user name",
	}, {
		name:         "illegal-user-name",
		given:        bs("root", "x", "0", "one@,two"),
		allowBadName: false,
		expectedErr:  "illegal user name",
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var actual etcGroupEntry
			actualErr := actual.decode(c.given, c.allowBadName)

			if expectedErr := c.expectedErr; expectedErr != "" {
				require.EqualError(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, c.expected, actual)
			}
		})
	}
}

func Test_etcGroupEntry_encode(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name         string
		given        etcGroupEntry
		allowBadName bool
		expected     [][]byte
		expectedErr  string
	}{{
		name:         "simple",
		given:        etcGroupEntry{b("root"), b("x"), 0, nil},
		allowBadName: false,
		expected:     bs("root", "x", "0", ""),
	}, {
		name:         "forbidden-bad-group-name",
		given:        etcGroupEntry{b("root@"), b("x"), 0, nil},
		allowBadName: false,
		expectedErr:  "illegal group name",
	}, {
		name:         "allowed-bad-group-name",
		given:        etcGroupEntry{b("root@"), b("x"), 0, nil},
		allowBadName: true,
		expected:     bs("root@", "x", "0", ""),
	}, {
		name:         "empty-group-name",
		given:        etcGroupEntry{b(""), b("x"), 0, nil},
		allowBadName: false,
		expectedErr:  "empty group name",
	}, {
		name:         "illegal-group-name",
		given:        etcGroupEntry{b("ro\tot"), b("x"), 0, nil},
		allowBadName: true,
		expectedErr:  "illegal group name",
	}, {
		name:         "too-long-group-name",
		given:        etcGroupEntry{b("a012345678901234567890123456789012"), b("x"), 0, nil},
		allowBadName: true,
		expectedErr:  "group name is longer than 32 characters",
	}, {
		name:         "one-user-name",
		given:        etcGroupEntry{b("root"), b("x"), 666, bs("one")},
		allowBadName: false,
		expected:     bs("root", "x", "666", "one"),
	}, {
		name:         "two-user-names",
		given:        etcGroupEntry{b("root"), b("x"), 123, bs("one", "two")},
		allowBadName: false,
		expected:     bs("root", "x", "123", "one,two"),
	}, {
		name:         "empty-user-name",
		given:        etcGroupEntry{b("root"), b("x"), 123, bs("", "two")},
		allowBadName: false,
		expectedErr:  "empty user name",
	}, {
		name:         "illegal-user-name",
		given:        etcGroupEntry{b("root"), b("x"), 123, bs("@one", "two")},
		allowBadName: false,
		expectedErr:  "illegal user name",
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual, actualErr := c.given.encode(c.allowBadName)

			if expectedErr := c.expectedErr; expectedErr != "" {
				require.EqualError(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, c.expected, actual)
			}
		})
	}
}
