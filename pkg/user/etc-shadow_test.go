//go:build moo && unix && !android

package user

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func Test_decodeEtcShadowFromReader(t *testing.T) {
	cases := []struct {
		name               string
		content            string
		allowBadName       bool
		shouldFailWith     error
		skipIllegalEntries bool
		expected           []etcShadowEntry
		expectedErr        string
	}{{
		name: "simple",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000

foo:XfooX:1735686000:10:100:::
   
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: false,
		expected: []etcShadowEntry{
			{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
			{b("foo"), b("XfooX"), 1735686000, 10, 100, 0, false, 0, false, 0, false},
			{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true},
		},
	}, {
		name: "forbidden-bad-name",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo@:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: false,
		expectedErr:  "cannot parse test:1: <TEST> illegal user name",
	}, {
		name: "allowed-bad-name",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo@:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expected: []etcShadowEntry{
			{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
			{b("foo@"), b("XfooX"), 1735686000, 10, 100, 0, false, 0, false, 0, false},
			{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true},
		},
	}, {
		name: "empty-user-name",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: false,
		expectedErr:  "cannot parse test:1: <TEST> empty user name",
	}, {
		name: "illegal-user-name",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
f	o:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> illegal user name",
	}, {
		name: "too-long-user-name",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
a012345678901234567890123456789012:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> user name is longer than 32 characters",
	}, {
		name: "empty-password",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo::1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> empty password",
	}, {
		name: "empty-last-change-at",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX::10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> empty last changed at",
	}, {
		name: "illegal-last-change-at",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:-1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> illegal last changed at",
	}, {
		name: "empty-minimum-age",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000::100:::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expected: []etcShadowEntry{
			{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
			{b("foo"), b("XfooX"), 1735686000, 0, 100, 0, false, 0, false, 0, false},
			{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true},
		},
	}, {
		name: "illegal-minimum-age",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:-10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> illegal minimum age",
	}, {
		name: "empty-maximum-age",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1767222000:10::::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> empty maximum age",
	}, {
		name: "illegal-maximum-age",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:-100:::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> illegal maximum age",
	}, {
		name: "illegal-warn-age",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:-50::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> illegal warn age",
	}, {
		name: "illegal-inactive-age",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100::-200:
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> illegal inactive age",
	}, {
		name: "illegal-expire-at",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::-666
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> illegal expire at",
	}, {
		name: "illegal-amount-of-columns",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100::::
bar:XbarX:1767222000:10:100:::1798758000`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: <TEST> illegal amount of columns; expected 8; but got: 9",
	}, {
		name: "skip-illegal-entry",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100::::
bar:XbarX:1767222000:10:100:::1798758000`,
		skipIllegalEntries: true,
		expected: []etcShadowEntry{
			{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
			{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true},
		},
	}, {
		name: "should-fail",
		content: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
		shouldFailWith: errors.New("expected"),
		expectedErr:    "cannot parse test:0: expected",
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var actual []etcShadowEntry
			actualErr := decodeEtcShadowFromReader(
				"test",
				strings.NewReader(c.content),
				c.allowBadName,
				func(entry *etcShadowEntry, lpErr error) (codecConsumerResult, error) {
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
