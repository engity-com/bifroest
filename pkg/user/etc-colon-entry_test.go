//go:build test

package user

import (
	"bytes"
	"strings"
	"testing"

	"github.com/echocat/slf4g/sdk/testlog"
	"github.com/stretchr/testify/require"
)

func Test_etcColonEntry_decode(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name            string
		given           string
		allowBadName    bool
		allowBadEntries bool
		expected        etcColonEntry[testEtcColonEntryValue, *testEtcColonEntryValue]
		expectedErr     string
	}{{
		name:         "simple",
		given:        `root:bar`,
		allowBadName: false,
		expected:     etcColonEntry[testEtcColonEntryValue, *testEtcColonEntryValue]{&testEtcColonEntryValue{b("root"), b("bar")}, nil},
	}, {
		name:         "forbidden-bad-name",
		given:        `root@:bar`,
		allowBadName: false,
		expectedErr:  "illegal user name",
	}, {
		name:         "allowed-bad-name",
		given:        `root@:bar`,
		allowBadName: true,
		expected:     etcColonEntry[testEtcColonEntryValue, *testEtcColonEntryValue]{&testEtcColonEntryValue{b("root@"), b("bar")}, nil},
	}, {
		name:        "illegal-amount-of-columns",
		given:       `roo:bar:`,
		expectedErr: "illegal amount of columns; expected 2; but got: 3",
	}, {
		name:            "skip-illegal-entry",
		given:           `root:bar:`,
		allowBadEntries: true,
		expected:        etcColonEntry[testEtcColonEntryValue, *testEtcColonEntryValue]{nil, b("root:bar:")},
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var actual etcColonEntry[testEtcColonEntryValue, *testEtcColonEntryValue]
			actualErr := actual.decode([]byte(c.given), 2, c.allowBadName, c.allowBadEntries)

			if expectedErr := c.expectedErr; expectedErr != "" {
				require.EqualError(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, actual, c.expected)
			}
		})
	}
}

func Test_etcColonEntry_encode(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name         string
		given        etcColonEntry[testEtcColonEntryValue, *testEtcColonEntryValue]
		allowBadName bool
		expected     string
		expectedErr  string
	}{{
		name:         "simple",
		given:        etcColonEntry[testEtcColonEntryValue, *testEtcColonEntryValue]{&testEtcColonEntryValue{b("root"), b("bar")}, nil},
		allowBadName: false,
		expected: `root:bar
`,
	}, {
		name:         "forbidden-bad-name",
		given:        etcColonEntry[testEtcColonEntryValue, *testEtcColonEntryValue]{&testEtcColonEntryValue{b("root@"), b("bar")}, nil},
		allowBadName: false,
		expectedErr:  "illegal user name",
	}, {
		name:         "allowed-bad-name",
		given:        etcColonEntry[testEtcColonEntryValue, *testEtcColonEntryValue]{&testEtcColonEntryValue{b("root@"), b("bar")}, nil},
		allowBadName: true,
		expected: `root@:bar
`,
	}, {
		name:  "keep-illegal-entry",
		given: etcColonEntry[testEtcColonEntryValue, *testEtcColonEntryValue]{nil, b("root:bar:")},
		expected: `root:bar:
`,
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var actual bytes.Buffer
			actualErr := c.given.encode(c.allowBadName, &actual)

			if expectedErr := c.expectedErr; expectedErr != "" {
				require.EqualError(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, actual.String(), c.expected)
			}
		})
	}
}

func Test_etcColonEntries_decode(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name            string
		given           string
		allowBadName    bool
		allowBadEntries bool
		expected        etcColonEntries[testEtcColonEntryValue, *testEtcColonEntryValue]
		expectedErr     string
	}{{
		name: "simple",
		given: `root:a

foo:b

bar:c`,
		allowBadName: false,
		expected: etcColonEntries[testEtcColonEntryValue, *testEtcColonEntryValue]{
			{&testEtcColonEntryValue{b("root"), b("a")}, nil},
			{nil, nil},
			{&testEtcColonEntryValue{b("foo"), b("b")}, nil},
			{nil, nil},
			{&testEtcColonEntryValue{b("bar"), b("c")}, nil},
		},
	}, {
		name: "forbidden-bad-name",
		given: `root:a
foo@:b
bar:c`,
		allowBadName: false,
		expectedErr:  "cannot parse entry at test:1: illegal user name",
	}, {
		name: "allowed-bad-name",
		given: `root:a
foo@:b
bar:c`,
		allowBadName: true,
		expected: etcColonEntries[testEtcColonEntryValue, *testEtcColonEntryValue]{
			{&testEtcColonEntryValue{b("root"), b("a")}, nil},
			{&testEtcColonEntryValue{b("foo@"), b("b")}, nil},
			{&testEtcColonEntryValue{b("bar"), b("c")}, nil},
		},
	}, {
		name: "illegal-amount-of-columns",
		given: `root:a
foo:b:
bar:c`,
		allowBadName: true,
		expectedErr:  "cannot parse entry at test:1: illegal amount of columns; expected 2; but got: 3",
	}, {
		name: "skip-illegal-entry",
		given: `root:a
foo:b:
bar:c`,
		allowBadEntries: true,
		expected: etcColonEntries[testEtcColonEntryValue, *testEtcColonEntryValue]{
			{&testEtcColonEntryValue{b("root"), b("a")}, nil},
			{nil, b("foo:b:")},
			{&testEtcColonEntryValue{b("bar"), b("c")}, nil},
		},
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reader := namedReader{strings.NewReader(c.given), "test"}
			var actual etcColonEntries[testEtcColonEntryValue, *testEtcColonEntryValue]
			actualErr := actual.decode(2, c.allowBadName, c.allowBadEntries, reader)

			if expectedErr := c.expectedErr; expectedErr != "" {
				require.EqualError(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, actual, c.expected)
			}
		})
	}
}

func Test_etcColonEntries_encode(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name         string
		expected     string
		allowBadName bool
		given        etcColonEntries[testEtcColonEntryValue, *testEtcColonEntryValue]
		expectedErr  string
	}{{
		name:         "simple",
		allowBadName: false,
		given: etcColonEntries[testEtcColonEntryValue, *testEtcColonEntryValue]{
			{&testEtcColonEntryValue{b("root"), b("a")}, nil},
			{nil, nil},
			{&testEtcColonEntryValue{b("foo"), b("b")}, nil},
			{nil, nil},
			{&testEtcColonEntryValue{b("bar"), b("c")}, nil},
		},
		expected: `root:a
foo:b
bar:c
`,
	}, {
		name: "forbidden-bad-name",
		given: etcColonEntries[testEtcColonEntryValue, *testEtcColonEntryValue]{
			{&testEtcColonEntryValue{b("root"), b("a")}, nil},
			{&testEtcColonEntryValue{b("foo@"), b("b")}, nil},
			{&testEtcColonEntryValue{b("bar"), b("c")}, nil},
		},
		allowBadName: false,
		expectedErr:  "cannot write at test:1: illegal user name",
	}, {
		name: "allowed-bad-name",
		given: etcColonEntries[testEtcColonEntryValue, *testEtcColonEntryValue]{
			{&testEtcColonEntryValue{b("root"), b("a")}, nil},
			{&testEtcColonEntryValue{b("foo@"), b("b")}, nil},
			{&testEtcColonEntryValue{b("bar"), b("c")}, nil},
		},
		allowBadName: true,
		expected: `root:a
foo@:b
bar:c
`,
	}, {
		name: "skip-illegal-entry",
		given: etcColonEntries[testEtcColonEntryValue, *testEtcColonEntryValue]{
			{&testEtcColonEntryValue{b("root"), b("a")}, nil},
			{nil, b("foo:b:")},
			{&testEtcColonEntryValue{b("bar"), b("c")}, nil},
		},
		expected: `root:a
foo:b:
bar:c
`,
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var actual namedBytesBuffer
			actualErr := c.given.encode(c.allowBadName, &actual)

			if expectedErr := c.expectedErr; expectedErr != "" {
				require.EqualError(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, c.expected, actual.String())
			}
		})
	}
}

type testEtcColonEntryValue struct {
	name  []byte
	other []byte
}

func (this *testEtcColonEntryValue) decode(line [][]byte, allowBadName bool) error {
	this.name = line[0]
	this.other = line[1]
	return validateUserName(this.name, allowBadName)
}

func (this *testEtcColonEntryValue) encode(allowBadName bool) ([][]byte, error) {
	if err := validateUserName(this.name, allowBadName); err != nil {
		return nil, err
	}
	return [][]byte{this.name, this.other}, nil
}
