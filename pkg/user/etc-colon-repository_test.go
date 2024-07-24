package user

import (
	"context"
	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEtcColonRepository_Init(t *testing.T) {
	cases := []struct {
		name   string
		passwd string
		group  string
		shadow string

		expectedPasswdEntries etcColonEntries[etcPasswdEntry, *etcPasswdEntry]
		expectedGroupEntries  etcColonEntries[etcGroupEntry, *etcGroupEntry]
		expectedShadowEntries etcColonEntries[etcShadowEntry, *etcShadowEntry]

		allowBadName          bool
		allowBadLine          bool
		onUnhandledAsyncError func(logger log.Logger, err error, detail string)

		expectedError string
	}{
		// default happy path
		{
			name: "all-content",
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{&etcPasswdEntry{b("foo"), b("abc"), 1, 2, b("Foo Name"), b("/home/foo"), b("/bin/foosh ")}, nil},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{&etcGroupEntry{b("foo"), b("abc"), 1, bs("aaa", "bbb")}, nil},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 1735686000, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true}, nil},
			},
		},

		// fail with bad names
		{
			name: "fail-with-bad-name-in-passwd",
			passwd: `root:x:0:0:root:/root:/bin/sh
foo@:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedError: ":0: illegal user name",
		},
		{
			name: "fail-with-bad-name-in-group",
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo@:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedError: ":0: illegal group name",
		},
		{
			name: "fail-with-bad-name-in-shadow",
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo@:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedError: ":0: illegal user name",
		},

		// allow bad names
		{
			name:         "allow-bad-name-in-passwd",
			allowBadName: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo@:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{&etcPasswdEntry{b("foo@"), b("abc"), 1, 2, b("Foo Name"), b("/home/foo"), b("/bin/foosh ")}, nil},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{&etcGroupEntry{b("foo"), b("abc"), 1, bs("aaa", "bbb")}, nil},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 1735686000, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true}, nil},
			},
		},
		{
			name:         "allow-bad-name-in-group",
			allowBadName: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo@:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{&etcPasswdEntry{b("foo"), b("abc"), 1, 2, b("Foo Name"), b("/home/foo"), b("/bin/foosh ")}, nil},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{&etcGroupEntry{b("foo@"), b("abc"), 1, bs("aaa", "bbb")}, nil},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 1735686000, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true}, nil},
			},
		},
		{
			name:         "allow-bad-name-in-shadow",
			allowBadName: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo@:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{&etcPasswdEntry{b("foo"), b("abc"), 1, 2, b("Foo Name"), b("/home/foo"), b("/bin/foosh ")}, nil},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{&etcGroupEntry{b("foo"), b("abc"), 1, bs("aaa", "bbb")}, nil},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true}, nil},
				{&etcShadowEntry{b("foo@"), b("XfooX"), 1735686000, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true}, nil},
			},
		},

		// fail with bad lines
		{
			name: "fail-with-line-in-passwd",
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh: 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedError: ":0: illegal amount of columns; expected 7; but got: 8",
		},
		{
			name: "fail-with-line-in-group",
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb:
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedError: ":0: illegal amount of columns; expected 4; but got: 5",
		},
		{
			name: "fail-with-line-in-shadow",
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100::::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedError: ":0: illegal amount of columns; expected 8; but got: 9",
		},

		// allow bad lines
		{
			name:         "allow-bad-lines-in-passwd",
			allowBadLine: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh :
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{nil, b("foo:abc:1:2:Foo Name:/home/foo:/bin/foosh :")},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{&etcGroupEntry{b("foo"), b("abc"), 1, bs("aaa", "bbb")}, nil},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 1735686000, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true}, nil},
			},
		},
		{
			name:         "allow-bad-lines-in-group",
			allowBadLine: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb:
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{&etcPasswdEntry{b("foo"), b("abc"), 1, 2, b("Foo Name"), b("/home/foo"), b("/bin/foosh ")}, nil},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{nil, b("foo:abc:1:aaa,bbb:")},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 1735686000, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true}, nil},
			},
		},
		{
			name:         "allow-bad-lines-in-shadow",
			allowBadLine: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100::::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{&etcPasswdEntry{b("foo"), b("abc"), 1, 2, b("Foo Name"), b("/home/foo"), b("/bin/foosh ")}, nil},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{&etcGroupEntry{b("foo"), b("abc"), 1, bs("aaa", "bbb")}, nil},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true}, nil},
				{nil, b("foo:XfooX:1735686000:10:100::::")},
				{&etcShadowEntry{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true}, nil},
			},
		},

		// allow bad lines by bad names
		{
			name:         "allow-bad-lines-in-passwd-by-bad-names",
			allowBadLine: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo@:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{nil, b("foo@:abc:1:2:Foo Name:/home/foo:/bin/foosh ")},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{&etcGroupEntry{b("foo"), b("abc"), 1, bs("aaa", "bbb")}, nil},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 1735686000, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true}, nil},
			},
		},
		{
			name:         "allow-bad-lines-in-group-by-bad-names",
			allowBadLine: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo@:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{&etcPasswdEntry{b("foo"), b("abc"), 1, 2, b("Foo Name"), b("/home/foo"), b("/bin/foosh ")}, nil},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{nil, b("foo@:abc:1:aaa,bbb")},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 1735686000, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true}, nil},
			},
		},
		{
			name:         "allow-bad-lines-in-shadow-by-bad-names",
			allowBadLine: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foo@:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{&etcPasswdEntry{b("foo"), b("abc"), 1, 2, b("Foo Name"), b("/home/foo"), b("/bin/foosh ")}, nil},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{&etcGroupEntry{b("foo"), b("abc"), 1, bs("aaa", "bbb")}, nil},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true}, nil},
				{nil, b("foo@:XfooX:1735686000:10:100:::")},
				{&etcShadowEntry{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true}, nil},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			passwdFile := newTestFile(t, "passwd", c.passwd)
			defer passwdFile.dispose(t)
			groupFile := newTestFile(t, "group", c.group)
			defer groupFile.dispose(t)
			shadowFile := newTestFile(t, "shadow", c.shadow)
			defer shadowFile.dispose(t)

			instance := EtcColonRepository{
				PasswdFilename:        string(passwdFile),
				GroupFilename:         string(groupFile),
				ShadowFilename:        string(shadowFile),
				AllowBadName:          c.allowBadName,
				AllowBadLine:          c.allowBadLine,
				OnUnhandledAsyncError: c.onUnhandledAsyncError,
			}

			actualErr := instance.Init(context.Background())
			if expectedErr := c.expectedError; expectedErr != "" {
				require.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)

				assert.Equal(t, c.expectedPasswdEntries, instance.handles.passwd.entries)
				assert.Equal(t, c.expectedGroupEntries, instance.handles.group.entries)
				assert.Equal(t, c.expectedShadowEntries, instance.handles.shadow.entries)
			}

			actualErr = instance.Close()
			require.NoError(t, actualErr)
		})
	}
}

func TestEtcColonRepository_OnFsEvents(t *testing.T) {
	passwdFile := newTestFile(t, "passwd", `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`)
	defer passwdFile.dispose(t)
	groupFile := newTestFile(t, "group", `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`)
	defer groupFile.dispose(t)
	shadowFile := newTestFile(t, "shadow", `root:XrootX:1704063600:10:100:50:200:1735686000
foo:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`)
	defer shadowFile.dispose(t)

	instance := EtcColonRepository{
		PasswdFilename: string(passwdFile),
		GroupFilename:  string(groupFile),
		ShadowFilename: string(shadowFile),
	}
	require.NoError(t, instance.Init(context.Background()))

	defer func() {
		assert.NoError(t, instance.Close())
	}()

	cases := []struct {
		name   string
		passwd string
		group  string
		shadow string

		expectedPasswdEntries etcColonEntries[etcPasswdEntry, *etcPasswdEntry]
		expectedGroupEntries  etcColonEntries[etcGroupEntry, *etcGroupEntry]
		expectedShadowEntries etcColonEntries[etcShadowEntry, *etcShadowEntry]

		onUnhandledAsyncError func(logger log.Logger, err error, detail string)

		expectedError string
	}{
		{
			name: "modify-entry",
			passwd: `root:x:0:0:root:/root:/bin/sh
foos:abc:1:2:Foo Name:/home/foo:/bin/foosh 
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foos:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
foos:XfooX:1735686000:10:100:::
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{&etcPasswdEntry{b("foos"), b("abc"), 1, 2, b("Foo Name"), b("/home/foo"), b("/bin/foosh ")}, nil},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{&etcGroupEntry{b("foos"), b("abc"), 1, bs("aaa", "bbb")}, nil},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true}, nil},
				{&etcShadowEntry{b("foos"), b("XfooX"), 1735686000, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true}, nil},
			},
		},
		{
			name: "entry-gone",
			passwd: `root:x:0:0:root:/root:/bin/sh
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
bar::12:ccc`,
			shadow: `root:XrootX:1704063600:10:100:50:200:1735686000
bar:XbarX:1767222000:10:100:::1798758000`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 1704063600, 10, 100, 50, true, 200, true, 1735686000, true}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 1767222000, 10, 100, 0, false, 0, false, 1798758000, true}, nil},
			},
		},
	}

	time.Sleep(50 * time.Millisecond)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			instance.OnUnhandledAsyncError = c.onUnhandledAsyncError

			passwdFile.update(t, c.passwd)
			groupFile.update(t, c.group)
			shadowFile.update(t, c.shadow)
			time.Sleep(50 * time.Millisecond)

			assert.Equal(t, c.expectedPasswdEntries, instance.handles.passwd.entries)
			assert.Equal(t, c.expectedGroupEntries, instance.handles.group.entries)
			assert.Equal(t, c.expectedShadowEntries, instance.handles.shadow.entries)
		})
	}
}

func newTestFile(t *testing.T, name string, content string) testFile {
	prefix := t.Name()
	prefix = strings.ReplaceAll(prefix, "/", "_")
	prefix = strings.ReplaceAll(prefix, "\\", "_")
	prefix = strings.ReplaceAll(prefix, "*", "_")
	prefix = strings.ReplaceAll(prefix, "$", "_")

	f, err := os.CreateTemp("", "go-test-"+prefix+"-"+name+"-*")
	require.NoError(t, err)

	_, err = io.Copy(f, strings.NewReader(content))
	require.NoError(t, err)

	require.NoError(t, f.Close())

	return testFile(f.Name())
}
