package user

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func Test_decodeEtcPasswdFromReader(t *testing.T) {
	cases := []struct {
		name           string
		content        string
		allowBadName   bool
		shouldFailWith error
		expected       []etcPasswdEntry
		expectedErr    string
	}{{
		name: "simple",
		content: `root:x:0:0:root:/root:/bin/sh

foo:abc:1:2:Foo Name:/home/foo:/bin/foosh 
   
bar::11:12::/home/bar:/bin/barsh`,
		allowBadName: false,
		expected: []etcPasswdEntry{
			{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")},
			{b("foo"), b("abc"), 1, 2, b("Foo Name"), b("/home/foo"), b("/bin/foosh ")},
			{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")},
		},
	}, {
		name: "forbidden-bad-name",
		content: `root:x:0:0:root:/root:/bin/sh
foo@:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12:Bar Name:/home/bar:/bin/barsh`,
		allowBadName: false,
		expectedErr:  "cannot parse test:1: illegal user name",
	}, {
		name: "allowed-bad-name",
		content: `root:x:0:0:root:/root:/bin/sh
foo@:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12:Bar Name:/home/bar:/bin/barsh`,
		allowBadName: true,
		expected: []etcPasswdEntry{
			{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")},
			{b("foo@"), b("abc"), 1, 2, b("Foo Name"), b("/home/foo"), b("/bin/foosh")},
			{b("bar"), b(""), 11, 12, b("Bar Name"), b("/home/bar"), b("/bin/barsh")},
		},
	}, {
		name: "empty-user-name",
		content: `root:x:0:0:root:/root:/bin/sh
:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12:Bar Name:/home/bar:/bin/barsh`,
		allowBadName: false,
		expectedErr:  "cannot parse test:1: empty user name",
	}, {
		name: "illegal-user-name",
		content: `root:x:0:0:root:/root:/bin/sh
f	o:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12:Bar Name:/home/bar:/bin/barsh`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: illegal user name",
	}, {
		name: "too-long-user-name",
		content: `root:x:0:0:root:/root:/bin/sh
a012345678901234567890123456789012:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12:Bar Name:/home/bar:/bin/barsh`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: user name is longer than 32 characters",
	}, {
		name:         "empty-uid",
		content:      `root:x::0:root:/root:/bin/sh`,
		allowBadName: true,
		expectedErr:  "cannot parse test:0: empty UID",
	}, {
		name:         "illegal-uid",
		content:      `root:x:-0:0:root:/root:/bin/sh`,
		allowBadName: true,
		expectedErr:  "cannot parse test:0: illegal UID",
	}, {
		name:         "empty-gid",
		content:      `root:x:0::root:/root:/bin/sh`,
		allowBadName: true,
		expectedErr:  "cannot parse test:0: empty GID",
	}, {
		name:         "illegal-gid",
		content:      `root:x:0:-0:root:/root:/bin/sh`,
		allowBadName: true,
		expectedErr:  "cannot parse test:0: illegal GID",
	}, {
		name: "too-long-geocs",
		content: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789:/home/foo:/bin/foosh
bar::11:12:Bar Name:/home/bar:/bin/barsh`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: geocs is longer than 255 characters",
	}, {
		name: "empty-home",
		content: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name::/bin/foosh
bar::11:12:Bar Name:/home/bar:/bin/barsh`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: empty home directory",
	}, {
		name: "too-long-home",
		content: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789:/bin/foosh
bar::11:12:Bar Name:/home/bar:/bin/barsh`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: home directory is longer than 255 characters",
	}, {
		name:         "illegal-home",
		content:      "root:x:0:0:root:/ro\000ot:/bin/sh",
		allowBadName: true,
		expectedErr:  "cannot parse test:0: illegal home directory",
	}, {
		name: "empty-shell",
		content: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:
bar::11:12:Bar Name:/home/bar:/bin/barsh`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: empty shell",
	}, {
		name: "too-long-shell",
		content: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789
bar::11:12:Bar Name:/home/bar:/bin/barsh`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: shell is longer than 255 characters",
	}, {
		name:         "illegal-shell",
		content:      "root:x:0:0:root:/root:/bin\000/sh",
		allowBadName: true,
		expectedErr:  "cannot parse test:0: illegal shell",
	}, {
		name: "illegal-amount-of-columns",
		content: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789
bar::11:12:Bar Name:/home/bar:/bin/barsh`,
		allowBadName: true,
		expectedErr:  "cannot parse test:1: illegal amount of columns; expected 7; but got: 6",
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var actual []etcPasswdEntry
			actualErr := decodeEtcPasswdFromReader(
				"test",
				strings.NewReader(c.content),
				c.allowBadName,
				func(entry *etcPasswdEntry) error {
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

func b(in string) []byte {
	return []byte(in)
}

func bs(ins ...string) [][]byte {
	result := make([][]byte, len(ins))
	for i, in := range ins {
		result[i] = b(in)
	}
	return result
}
