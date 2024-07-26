//go:build unix

package user

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_etcShadowEntry_decode(t *testing.T) {
	cases := []struct {
		name         string
		given        [][]byte
		allowBadName bool
		expected     etcShadowEntry
		expectedErr  string
	}{{
		name:         "simple",
		given:        bs("root", "XrootX", "1704063600", "10", "100", "50", "200", "1735686000"),
		allowBadName: false,
		expected:     etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
	}, {
		name:         "without-all-optionals",
		given:        bs("root", "XrootX", "1704063600", "10", "100", "", "", ""),
		allowBadName: false,
		expected:     etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 0, false, 0, false, 0, false},
	}, {
		name:         "with-expire-ts",
		given:        bs("root", "XrootX", "1704063600", "10", "100", "", "", "1798758000"),
		allowBadName: false,
		expected:     etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 0, false, 0, false, 1798758000, true},
	}, {
		name:         "with-inactive-days",
		given:        bs("root", "XrootX", "1704063600", "10", "100", "", "200", ""),
		allowBadName: false,
		expected:     etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 0, false, 200, true, 0, false},
	}, {
		name:         "with-warn-days",
		given:        bs("root", "XrootX", "1704063600", "10", "100", "50", "", ""),
		allowBadName: false,
		expected:     etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 0, false, 0, false},
	}, {
		name:         "forbidden-bad-name",
		given:        bs("root@", "XrootX", "1704063600", "10", "100", "50", "200", "1735686000"),
		allowBadName: false,
		expectedErr:  "illegal user name",
	}, {
		name:         "allowed-bad-name",
		given:        bs("root@", "XrootX", "1704063600", "10", "100", "50", "200", "1735686000"),
		allowBadName: true,
		expected:     etcShadowEntry{b("root@"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
	}, {
		name:         "empty-user-name",
		given:        bs("", "XrootX", "1704063600", "10", "100", "50", "200", "1735686000"),
		allowBadName: true,
		expectedErr:  "empty user name",
	}, {
		name:         "illegal-user-name",
		given:        bs("ro\tot", "XrootX", "1704063600", "10", "100", "50", "200", "1735686000"),
		allowBadName: true,
		expectedErr:  "illegal user name",
	}, {
		name:         "too-long-user-name",
		given:        bs("a012345678901234567890123456789012", "XrootX", "1704063600", "10", "100", "50", "200", "1735686000"),
		allowBadName: true,
		expectedErr:  "user name is longer than 32 characters",
	}, {
		name:         "empty-password",
		given:        bs("root", "", "1704063600", "10", "100", "50", "200", "1735686000"),
		allowBadName: true,
		expectedErr:  "empty password",
	}, {
		name:         "empty-last-change-at",
		given:        bs("root", "XrootX", "", "10", "100", "50", "200", "1735686000"),
		allowBadName: true,
		expectedErr:  "empty last changed at",
	}, {
		name:         "illegal-last-change-at",
		given:        bs("root", "XrootX", "-1704063600", "10", "100", "50", "200", "1735686000"),
		allowBadName: true,
		expectedErr:  "illegal last changed at",
	}, {
		name:         "empty-minimum-age",
		given:        bs("root", "XrootX", "1704063600", "", "100", "50", "200", "1735686000"),
		allowBadName: true,
		expected:     etcShadowEntry{b("root"), b("XrootX"), 1704063600, 0, 100, 50, true, 200, true, 1735686000, true},
	}, {
		name:         "illegal-minimum-age",
		given:        bs("root", "XrootX", "1704063600", "-10", "100", "50", "200", "1735686000"),
		allowBadName: true,
		expectedErr:  "illegal minimum age",
	}, {
		name:         "empty-maximum-age",
		given:        bs("root", "XrootX", "1704063600", "10", "", "50", "200", "1735686000"),
		allowBadName: true,
		expectedErr:  "empty maximum age",
	}, {
		name:         "illegal-maximum-age",
		given:        bs("root", "XrootX", "1704063600", "10", "-100", "50", "200", "1735686000"),
		allowBadName: true,
		expectedErr:  "illegal maximum age",
	}, {
		name:         "illegal-warn-age",
		given:        bs("root", "XrootX", "1704063600", "10", "100", "-50", "200", "1735686000"),
		allowBadName: true,
		expectedErr:  "illegal warn age",
	}, {
		name:         "illegal-inactive-age",
		given:        bs("root", "XrootX", "1704063600", "10", "100", "50", "-200", "1735686000"),
		allowBadName: true,
		expectedErr:  "illegal inactive age",
	}, {
		name:         "illegal-expire-at",
		given:        bs("root", "XrootX", "1704063600", "10", "100", "50", "200", "-1735686000"),
		allowBadName: true,
		expectedErr:  "illegal expire at",
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var actual etcShadowEntry
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

func Test_etcShadowEntry_encode(t *testing.T) {
	cases := []struct {
		name         string
		given        etcShadowEntry
		allowBadName bool
		expected     [][]byte
		expectedErr  string
	}{{
		name:         "simple",
		given:        etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
		allowBadName: false,
		expected:     bs("root", "XrootX", "1704063600", "10", "100", "50", "200", "1735686000"),
	}, {
		name:         "without-all-optionals",
		given:        etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 0, false, 0, false, 0, false},
		allowBadName: false,
		expected:     bs("root", "XrootX", "1704063600", "10", "100", "", "", ""),
	}, {
		name:         "all-empty-what-can-be-empty",
		given:        etcShadowEntry{b("root"), b("XrootX"), 0, 0, 0, 0, false, 0, false, 0, false},
		allowBadName: false,
		expected:     bs("root", "XrootX", "0", "0", "0", "", "", ""),
	}, {
		name:         "forbidden-bad-name",
		given:        etcShadowEntry{b("root@"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
		allowBadName: false,
		expectedErr:  "illegal user name",
	}, {
		name:         "allowed-bad-name",
		given:        etcShadowEntry{b("root@"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
		allowBadName: true,
		expected:     bs("root@", "XrootX", "1704063600", "10", "100", "50", "200", "1735686000"),
	}, {
		name:         "empty-user-name",
		given:        etcShadowEntry{b(""), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
		allowBadName: true,
		expectedErr:  "empty user name",
	}, {
		name:         "illegal-user-name",
		given:        etcShadowEntry{b("ro\tot"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
		allowBadName: true,
		expectedErr:  "illegal user name",
	}, {
		name:         "too-long-user-name",
		given:        etcShadowEntry{b("a012345678901234567890123456789012"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
		allowBadName: true,
		expectedErr:  "user name is longer than 32 characters",
	}, {
		name:         "empty-password",
		given:        etcShadowEntry{b("root"), b(""), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true},
		allowBadName: true,
		expectedErr:  "empty password",
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
