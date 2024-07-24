//go:build moo && unix && !android

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
				func(entry *etcGroupEntry, lpErr error) (codecConsumerResult, error) {
					if lpErr != nil {
						if c.skipIllegalEntries {
							return codecConsumerResultContinue, nil
						}
						return 0, fmt.Errorf("<TEST> %w", lpErr)
					}
					if err := c.shouldFailWith; err != nil {
						return 0, err
					}
					actual = append(actual, *entry)
					return codecConsumerResultContinue, nil
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

func Test_modifyEtcGroupFromReaderToWriter(t *testing.T) {
	cases := []struct {
		name               string
		content            string
		allowBadName       bool
		skipIllegalEntries bool
		shouldFailWith     error
		newEntries         []etcGroupEntry
		modifyEntries      map[string]codecModifyEntry[etcGroupEntry]
		expected           string
		expectedErr        string
	}{{
		name: "keep-as-it-is",
		content: `root:x:0:

foo:abc:1:aaa,bbb

bar::12:ccc`,
		allowBadName: false,
		expected: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc
`,
	}, {
		name: "modify-an-entry",
		content: `root:x:0:

foo:abc:1:aaa,bbb

bar::12:ccc`,
		allowBadName: false,
		modifyEntries: map[string]codecModifyEntry[etcGroupEntry]{
			"foo": {codecHandlerResultUpdate, etcGroupEntry{b("new"), b("XnewX"), 666, bs("a", "b", "c")}},
		},
		expected: `root:x:0:
new,XnewX,666,a,b,c
bar::12:ccc
`,
	}, {
		name: "keep-an-entry",
		content: `root:x:0:

foo:abc:1:aaa,bbb

bar::12:ccc`,
		allowBadName: false,
		modifyEntries: map[string]codecModifyEntry[etcGroupEntry]{
			"foo": {codecHandlerResultContinue, etcGroupEntry{b("new"), b("XnewX"), 666, bs("a", "b", "c")}},
		},
		expected: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc
`,
	}, {
		name: "delete-an-entry",
		content: `root:x:0:

foo:abc:1:aaa,bbb

bar::12:ccc`,
		allowBadName: false,
		modifyEntries: map[string]codecModifyEntry[etcGroupEntry]{
			"foo": {codecHandlerResultSkip, etcGroupEntry{b("new"), b("XnewX"), 666, bs("a", "b", "c")}},
		},
		expected: `root:x:0:
bar::12:ccc
`,
	}, {
		name: "add-an-entry",
		content: `root:x:0:

foo:abc:1:aaa,bbb

bar::12:ccc`,
		allowBadName: false,
		newEntries: []etcGroupEntry{
			{b("new"), b("XnewX"), 666, bs("a", "b", "c")},
		},
		expected: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc
new,XnewX,666,a,b,c
`,
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var newEntriesI int

			var actual strings.Builder
			actualErr := modifyEtcGroupFromReaderToWriter(
				"test",
				strings.NewReader(c.content),
				&actual,
				c.allowBadName,
				func(entry *etcGroupEntry, lpErr error) (codecHandlerResult, error) {
					if lpErr != nil {
						if c.skipIllegalEntries {
							return codecHandlerResultContinue, nil
						}
						return 0, fmt.Errorf("<TEST> %w", lpErr)
					}
					if err := c.shouldFailWith; err != nil {
						return 0, err
					}
					if nv, ok := c.modifyEntries[string(entry.name)]; ok {
						*entry = nv.v
						return nv.r, nil
					}
					return codecHandlerResultContinue, nil
				}, func(allowBadName bool) (*etcGroupEntry, error) {
					if len(c.newEntries) <= newEntriesI {
						return nil, nil
					}
					i := newEntriesI
					newEntriesI++
					return &c.newEntries[i], nil
				})

			if expectedErr := c.expectedErr; expectedErr != "" {
				require.EqualError(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, c.expected, actual.String())
			}
		})
	}
}
