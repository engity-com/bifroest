package user

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func Test_decodeEtcGroupFromReader(t *testing.T) {
	cases := []struct {
		name               string
		content            string
		allowBadName       bool
		skipIllegalEntries bool
		shouldFailWith     error
		expected           []etcGroupEntry
		expectedErr        string
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
		expectedErr:  "cannot parse test:1: <TEST> illegal group name",
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
		expectedErr:  "cannot parse test:1: <TEST> empty group name",
	}, {
		name: "illegal-group-name",
		content: `root:x:0:
fo	o@:abc:1:aaa,bbb
bar::12:ccc`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> illegal group name",
	}, {
		name: "too-long-group-name",
		content: `root:x:0:
a012345678901234567890123456789012:abc:1:aaa,bbb
bar::12:ccc`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> group name is longer than 32 characters",
	}, {
		name: "empty-gid",
		content: `root:x:0:
foo:abc::aaa,bbb
bar::12:ccc`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> empty GID",
	}, {
		name: "illegal-gid",
		content: `root:x:0:
foo:abc:-1:aaa,bbb
bar::12:ccc`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> illegal GID",
	}, {
		name: "empty-user-name",
		content: `root:x:0:
foo:abc:1:,bbb
bar::12:ccc`,
		allowBadName: false,
		expectedErr:  "cannot parse test:1: <TEST> empty user name",
	}, {
		name: "illegal-user-name",
		content: `root:x:0:
foo:abc:1:aa@a,bbb
bar::12:ccc`,
		allowBadName: false,
		expectedErr:  "cannot parse test:1: <TEST> illegal user name",
	}, {
		name: "illegal-amount-of-columns",
		content: `root:x:0:
foo:abc:1:aaa,bbb:
bar::12:ccc`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> illegal amount of columns; expected 4; but got: 5",
	}, {
		name: "skip-illegal-entry",
		content: `root:x:0:
foo:abc:1:aaa,bbb:
bar::12:ccc`,
		skipIllegalEntries: true,
		expected: []etcGroupEntry{
			{b("root"), b("x"), 0, nil},
			{b("bar"), b(""), 12, bs("ccc")},
		},
	}, {
		name: "should-fail",
		content: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
		shouldFailWith: errors.New("expected"),
		expectedErr:    "cannot parse test:0: expected",
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var actual []etcGroupEntry
			actualErr := decodeEtcGroupFromReader(
				"test",
				strings.NewReader(c.content),
				c.allowBadName,
				func(entry *etcGroupEntry, lpErr error) error {
					if lpErr != nil {
						if c.skipIllegalEntries {
							return nil
						}
						return fmt.Errorf("<TEST> %w", lpErr)
					}
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
