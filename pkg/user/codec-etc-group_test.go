package user

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func Test_decodeEtcGroupFromReader(t *testing.T) {
	cases := []struct {
		name           string
		content        string
		allowBadName   bool
		shouldFailWith error
		expected       []etcGroupEntry
		expectedErr    string
	}{{
		name: "simple",
		content: `root:x:0:

foo:abc:1:aaa,bbb

bar::12:ccc`,
		allowBadName: false,
		expected: []etcGroupEntry{
			{b("root"), b("x"), 0, nil},
			{b("foo"), b("abc"), 1, bs("aaa", "bbb")},
			{b("bar"), b(""), 12, bs("ccc")},
		},
	}, {
		name: "forbidden-bad-name",
		content: `root:x:0:
foo@:abc:1:aaa,bbb
bar::12:ccc`,
		allowBadName: false,
		expectedErr:  "cannot parse test:1: illegal group name",
	}, {
		name: "allowed-bad-name",
		content: `root:x:0:
foo@:abc:1:aaa,bbb
bar::12:ccc`,
		allowBadName: true,
		expected: []etcGroupEntry{
			{b("root"), b("x"), 0, nil},
			{b("foo@"), b("abc"), 1, bs("aaa", "bbb")},
			{b("bar"), b(""), 12, bs("ccc")},
		},
	}, {
		name: "empty-group-name",
		content: `root:x:0:
:abc:1:aaa,bbb
bar::12:ccc`,
		allowBadName: false,
		expectedErr:  "cannot parse test:1: empty group name",
	}, {
		name: "illegal-group-name",
		content: `root:x:0:
fo	o@:abc:1:aaa,bbb
bar::12:ccc`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: illegal group name",
	}, {
		name: "too-long-group-name",
		content: `root:x:0:
a012345678901234567890123456789012:abc:1:aaa,bbb
bar::12:ccc`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: group name is longer than 32 characters",
	}, {
		name: "empty-gid",
		content: `root:x:0:
foo:abc::aaa,bbb
bar::12:ccc`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: empty GID",
	}, {
		name: "illegal-gid",
		content: `root:x:0:
foo:abc:-1:aaa,bbb
bar::12:ccc`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: illegal GID",
	}, {
		name: "empty-user-name",
		content: `root:x:0:
foo:abc:1:,bbb
bar::12:ccc`,
		allowBadName: false,
		expectedErr:  "cannot parse test:1: empty user name",
	}, {
		name: "illegal-user-name",
		content: `root:x:0:
foo:abc:1:aa@a,bbb
bar::12:ccc`,
		allowBadName: false,
		expectedErr:  "cannot parse test:1: illegal user name",
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var actual []etcGroupEntry
			actualErr := decodeEtcGroupFromReader(
				"test",
				strings.NewReader(c.content),
				c.allowBadName,
				func(entry *etcGroupEntry) error {
					if err := c.shouldFailWith; err != nil {
						return err
					}
					actual = append(actual, *entry)
					return nil
				})

			if expectedErr := c.expectedErr; expectedErr != "" {
				require.EqualError(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, actual, c.expected)
			}
		})
	}
}
