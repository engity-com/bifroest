//go:build unix

package user

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/echocat/slf4g/sdk/testlog"
	"github.com/echocat/slf4g/testing/recording"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
)

func Test_EtcColonRepository_Init(t *testing.T) {
	testlog.Hook(t)

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
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh$space$
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{&etcPasswdEntry{b("foo"), b("abc"), 1, 2, b("Foo Name"), b("/home/foo"), b("/bin/foosh ")}, nil},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{&etcGroupEntry{b("foo"), b("abc"), 1, bs("foo", "bbb")}, nil},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("bar")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 19722, 10, 100, 50, true, 200, true, 20088, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 20088, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 20453, 10, 100, 0, false, 0, false, 20818, true}, nil},
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
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
			expectedError: ":1: illegal user name",
		},
		{
			name: "fail-with-bad-name-in-group",
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo@:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
			expectedError: ":1: illegal group name",
		},
		{
			name: "fail-with-bad-name-in-shadow",
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo@:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
			expectedError: ":1: illegal user name",
		},

		// allow bad names
		{
			name:         "allow-bad-name-in-passwd",
			allowBadName: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo@:abc:1:2:Foo Name:/home/foo:/bin/foosh$space$
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
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
				{&etcShadowEntry{b("root"), b("XrootX"), 19722, 10, 100, 50, true, 200, true, 20088, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 20088, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 20453, 10, 100, 0, false, 0, false, 20818, true}, nil},
			},
		},
		{
			name:         "allow-bad-name-in-group",
			allowBadName: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh$space$
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo@:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
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
				{&etcShadowEntry{b("root"), b("XrootX"), 19722, 10, 100, 50, true, 200, true, 20088, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 20088, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 20453, 10, 100, 0, false, 0, false, 20818, true}, nil},
			},
		},
		{
			name:         "allow-bad-name-in-shadow",
			allowBadName: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh$space$
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo@:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
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
				{&etcShadowEntry{b("root"), b("XrootX"), 19722, 10, 100, 50, true, 200, true, 20088, true}, nil},
				{&etcShadowEntry{b("foo@"), b("XfooX"), 20088, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 20453, 10, 100, 0, false, 0, false, 20818, true}, nil},
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
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
			expectedError: ":1: illegal amount of columns; expected 7; but got: 8",
		},
		{
			name: "fail-with-line-in-group",
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb:
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
			expectedError: ":1: illegal amount of columns; expected 4; but got: 5",
		},
		{
			name: "fail-with-line-in-shadow",
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100:::::
bar:XbarX:20453:10:100:::20818:`,
			expectedError: ":1: illegal amount of columns; expected 9; but got: 10",
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
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
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
				{&etcShadowEntry{b("root"), b("XrootX"), 19722, 10, 100, 50, true, 200, true, 20088, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 20088, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 20453, 10, 100, 0, false, 0, false, 20818, true}, nil},
			},
		},
		{
			name:         "allow-bad-lines-in-group",
			allowBadLine: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh$space$
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb:
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
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
				{&etcShadowEntry{b("root"), b("XrootX"), 19722, 10, 100, 50, true, 200, true, 20088, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 20088, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 20453, 10, 100, 0, false, 0, false, 20818, true}, nil},
			},
		},
		{
			name:         "allow-bad-lines-in-shadow",
			allowBadLine: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh$space$
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100:::::
bar:XbarX:20453:10:100:::20818:`,
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
				{&etcShadowEntry{b("root"), b("XrootX"), 19722, 10, 100, 50, true, 200, true, 20088, true}, nil},
				{nil, b("foo:XfooX:20088:10:100:::::")},
				{&etcShadowEntry{b("bar"), b("XbarX"), 20453, 10, 100, 0, false, 0, false, 20818, true}, nil},
			},
		},

		// allow bad lines by bad names
		{
			name:         "allow-bad-lines-in-passwd-by-bad-names",
			allowBadLine: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo@:abc:1:2:Foo Name:/home/foo:/bin/foosh$space$
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
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
				{&etcShadowEntry{b("root"), b("XrootX"), 19722, 10, 100, 50, true, 200, true, 20088, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 20088, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 20453, 10, 100, 0, false, 0, false, 20818, true}, nil},
			},
		},
		{
			name:         "allow-bad-lines-in-group-by-bad-names",
			allowBadLine: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh$space$
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo@:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
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
				{&etcShadowEntry{b("root"), b("XrootX"), 19722, 10, 100, 50, true, 200, true, 20088, true}, nil},
				{&etcShadowEntry{b("foo"), b("XfooX"), 20088, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 20453, 10, 100, 0, false, 0, false, 20818, true}, nil},
			},
		},
		{
			name:         "allow-bad-lines-in-shadow-by-bad-names",
			allowBadLine: true,
			passwd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh$space$
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foo@:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
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
				{&etcShadowEntry{b("root"), b("XrootX"), 19722, 10, 100, 50, true, 200, true, 20088, true}, nil},
				{nil, b("foo@:XfooX:20088:10:100::::")},
				{&etcShadowEntry{b("bar"), b("XbarX"), 20453, 10, 100, 0, false, 0, false, 20818, true}, nil},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)
			passwdFile := dir.file("passwd").setContent(c.passwd)
			groupFile := dir.file("group").setContent(c.group)
			shadowFile := dir.file("shadow").setContent(c.shadow)

			var asyncError error
			instance := EtcColonRepository{
				PasswdFilename:        passwdFile.name(),
				GroupFilename:         groupFile.name(),
				ShadowFilename:        shadowFile.name(),
				AllowBadName:          &c.allowBadName,
				AllowBadLine:          &c.allowBadLine,
				OnUnhandledAsyncError: c.onUnhandledAsyncError,
			}
			if instance.OnUnhandledAsyncError == nil {
				instance.OnUnhandledAsyncError = func(_ log.Logger, err error, _ string) {
					asyncError = err
				}
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

			require.NoError(t, asyncError)
		})
	}
}

func Test_EtcColonRepository_Init_withNonExistingFiles(t *testing.T) {
	testlog.Hook(t)

	instance := EtcColonRepository{
		PasswdFilename: "/@/!/foo/passwd",
		GroupFilename:  "/@/!/foo/group",
		ShadowFilename: "/@/!/foo/shadow",
	}

	actualErr := instance.Init(context.Background())
	assert.ErrorContains(t, actualErr, "open /@/!/foo/passwd: no such file or directory")
}

func Test_EtcColonRepository_Init_withNonExistingFilesButAllowedToCreate(t *testing.T) {
	testlog.Hook(t)

	dir := newTestDir(t)

	instance := EtcColonRepository{
		PasswdFilename:      dir.child("etc", "passwd"),
		GroupFilename:       dir.child("etc", "group"),
		ShadowFilename:      dir.child("etc", "shadow"),
		CreateFilesIfAbsent: common.P(true),
	}

	actualErr := instance.Init(context.Background())
	assert.NoError(t, actualErr)
	assert.FileExists(t, dir.child("etc", "passwd"))
	assert.FileExists(t, dir.child("etc", "group"))
	assert.FileExists(t, dir.child("etc", "shadow"))
}

func Test_EtcColonRepository_onFsEvents(t *testing.T) {
	testlog.Hook(t)

	dir := newTestDir(t)
	passwdFile := dir.file("passwd").setContent(`root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`)
	groupFile := dir.file("group").setContent(`root:x:0:
foo:abc:1:aaa,bbb
bar::12:ccc`)
	shadowFile := dir.file("shadow").setContent(`root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`)

	instance := EtcColonRepository{
		PasswdFilename:          passwdFile.name(),
		GroupFilename:           groupFile.name(),
		ShadowFilename:          shadowFile.name(),
		FileSystemSyncThreshold: 1,
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

		expectedError string
	}{
		{
			name: "modify-entry",
			passwd: `root:x:0:0:root:/root:/bin/sh
foos:abc:1:2:Foo Name:/home/foo:/bin/foosh$space$
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
foos:abc:1:aaa,bbb
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
foos:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,
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
				{&etcShadowEntry{b("root"), b("XrootX"), 19722, 10, 100, 50, true, 200, true, 20088, true}, nil},
				{&etcShadowEntry{b("foos"), b("XfooX"), 20088, 10, 100, 0, false, 0, false, 0, false}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 20453, 10, 100, 0, false, 0, false, 20818, true}, nil},
			},
		},
		{
			name: "entry-gone",
			passwd: `root:x:0:0:root:/root:/bin/sh
bar::11:12::/home/bar:/bin/barsh`,
			group: `root:x:0:
bar::12:ccc`,
			shadow: `root:XrootX:19722:10:100:50:200:20088:
bar:XbarX:20453:10:100:::20818:`,
			expectedPasswdEntries: etcColonEntries[etcPasswdEntry, *etcPasswdEntry]{
				{&etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")}, nil},
				{&etcPasswdEntry{b("bar"), b(""), 11, 12, b(""), b("/home/bar"), b("/bin/barsh")}, nil},
			},
			expectedGroupEntries: etcColonEntries[etcGroupEntry, *etcGroupEntry]{
				{&etcGroupEntry{b("root"), b("x"), 0, nil}, nil},
				{&etcGroupEntry{b("bar"), b(""), 12, bs("ccc")}, nil},
			},
			expectedShadowEntries: etcColonEntries[etcShadowEntry, *etcShadowEntry]{
				{&etcShadowEntry{b("root"), b("XrootX"), 19722, 10, 100, 50, true, 200, true, 20088, true}, nil},
				{&etcShadowEntry{b("bar"), b("XbarX"), 20453, 10, 100, 0, false, 0, false, 20818, true}, nil},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var unhandledAsyncError error
			instance.OnUnhandledAsyncError = func(logger log.Logger, err error, detail string) {
				unhandledAsyncError = err
			}

			passwdFile.setContent(c.passwd)
			groupFile.setContent(c.group)
			shadowFile.setContent(c.shadow)
			time.Sleep(150 * time.Millisecond)

			instance.mutex.RLock()
			defer instance.mutex.RUnlock()
			assert.Equal(t, c.expectedPasswdEntries, instance.handles.passwd.entries)
			assert.Equal(t, c.expectedGroupEntries, instance.handles.group.entries)
			assert.Equal(t, c.expectedShadowEntries, instance.handles.shadow.entries)

			assert.NoError(t, unhandledAsyncError)
		})
	}
}

func Test_EtcColonRepository_Ensure(t *testing.T) {
	testlog.Hook(t)

	dir := newTestDir(t)

	skel := dir.dir("skel")

	defer func() {
		etcColonRepositoryChownFunc = os.Chown
	}()
	etcColonRepositoryChownFunc = func(string, int, int) error { return nil }

	cases := []struct {
		name        string
		requirement Requirement
		opts        *EnsureOpts

		expected       User
		expectedPasswd string
		expectedGroup  string
		expectedShadow string
		expectedResult EnsureResult

		expectedErr string
	}{{
		name: "full-new",
		requirement: Requirement{
			Name:        "test",
			DisplayName: "XtestX",
			Group: GroupRequirement{
				Name: "testg",
			},
			Groups:  GroupRequirements{{Name: "testg"}},
			Shell:   "/bin/a/shell",
			HomeDir: dir.child("full-new"),
			Skel:    skel.name(),
		},

		expectedResult: EnsureResultCreated,
		expected:       User{"test", "XtestX", 1000, Group{1000, "testg"}, Groups{{1000, "testg"}}, "/bin/a/shell", dir.child("full-new")},
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh
test:x:1000:1000:XtestX:` + dir.child("full-new") + `:/bin/a/shell
$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
testg:x:1000:test
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:
test:\*:\d+:0:99999:7:::
$`,
	}, {
		name: "full-new-by-id",
		requirement: Requirement{
			Uid:         common.P[Id](666),
			DisplayName: "XtestX",
			Group: GroupRequirement{
				Name: "testg",
			},
			Groups:  GroupRequirements{{Name: "testg"}},
			Shell:   "/bin/a/shell",
			HomeDir: dir.child("full-new-by-id"),
			Skel:    skel.name(),
		},

		expectedResult: EnsureResultCreated,
		expected:       User{"u666", "XtestX", 666, Group{1000, "testg"}, Groups{{1000, "testg"}}, "/bin/a/shell", dir.child("full-new-by-id")},
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh
u666:x:666:1000:XtestX:` + dir.child("full-new-by-id") + `:/bin/a/shell
$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
testg:x:1000:u666
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:
u666:\*:\d+:0:99999:7:::
$`,
	}, {
		name: "add-to-existing-group",
		requirement: Requirement{
			Name:        "test",
			DisplayName: "XtestX",
			Group: GroupRequirement{
				Name: "root",
			},
			Groups:  GroupRequirements{{Name: "foo"}},
			Shell:   "/bin/a/shell",
			HomeDir: dir.child("add-to-existing-group"),
			Skel:    skel.name(),
		},

		expectedResult: EnsureResultCreated,
		expected:       User{"test", "XtestX", 1000, Group{0, "root"}, Groups{{1, "foo"}}, "/bin/a/shell", dir.child("add-to-existing-group")},
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh
test:x:1000:0:XtestX:` + dir.child("add-to-existing-group") + `:/bin/a/shell
$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb,test
bar::12:bar
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:
test:\*:\d+:0:99999:7:::
$`,
	}, {
		name: "update-existing-to-defaults",
		requirement: Requirement{
			Name:  "foo",
			Shell: "/bin/a/shell",
		},

		expectedResult: EnsureResultModified,
		expected:       User{"foo", "", 1, Group{1, "foo"}, Groups{{1000, "bifroest"}}, "/bin/a/shell", "/home/foo"},
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1::/home/foo:/bin/a/shell
bar::11:12::/home/bar:/bin/barsh
$`,
		expectedGroup: `^root:x:0:
foo:abc:1:bbb
bar::12:bar
bifroest:x:1000:foo
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:
$`,
	}, {
		name: "update-existing-to-defaults-by-id",
		requirement: Requirement{
			Uid:   common.P[Id](1),
			Shell: "/bin/a/shell",
		},

		expectedResult: EnsureResultModified,
		expected:       User{"u1", "", 1, Group{1000, "u1"}, Groups{{1001, "bifroest"}}, "/bin/a/shell", "/home/u1"},
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
u1:abc:1:1000::/home/u1:/bin/a/shell
bar::11:12::/home/bar:/bin/barsh
$`,
		expectedGroup: `^root:x:0:
foo:abc:1:bbb
bar::12:bar
u1:x:1000:
bifroest:x:1001:u1
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
u1:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:
$`,
	}, {
		name: "update-existing-to-defaults-by-name",
		requirement: Requirement{
			Name:  "foo",
			Uid:   common.P[Id](666),
			Shell: "/bin/a/shell",
		},

		expectedResult: EnsureResultModified,
		expected:       User{"foo", "", 666, Group{1, "foo"}, Groups{{1000, "bifroest"}}, "/bin/a/shell", "/home/foo"},
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:666:1::/home/foo:/bin/a/shell
bar::11:12::/home/bar:/bin/barsh
$`,
		expectedGroup: `^root:x:0:
foo:abc:1:bbb
bar::12:bar
bifroest:x:1000:foo
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:
$`,
	}, {
		name: "update-exiting-to-new-group",
		requirement: Requirement{
			Name:   "foo",
			Shell:  "/bin/a/shell",
			Group:  GroupRequirement{Name: "foo1"},
			Groups: GroupRequirements{{Name: "foo2"}},
		},

		expectedResult: EnsureResultModified,
		expected:       User{"foo", "", 1, Group{1000, "foo1"}, Groups{{1001, "foo2"}}, "/bin/a/shell", "/home/foo"},
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1000::/home/foo:/bin/a/shell
bar::11:12::/home/bar:/bin/barsh
$`,
		expectedGroup: `^root:x:0:
foo:abc:1:bbb
bar::12:bar
foo1:x:1000:
foo2:x:1001:foo
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:
$`,
	}, {
		name: "unchanged",
		requirement: Requirement{
			Name:        "foo",
			Shell:       "/bin/foosh",
			HomeDir:     "/home/foo",
			DisplayName: "Foo Name",
			Group:       GroupRequirement{Name: "foo"},
			Groups:      GroupRequirements{{Name: "foo"}},
		},

		expectedResult: EnsureResultUnchanged,
		expected:       User{"foo", "Foo Name", 1, Group{1, "foo"}, Groups{{1, "foo"}}, "/bin/foosh", "/home/foo"},
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}, {
		name: "unchanged-if-all-else-forbidden",
		requirement: Requirement{
			Name:        "foo",
			Shell:       "/bin/foosh",
			HomeDir:     "/home/foo",
			DisplayName: "Foo Name",
			Group:       GroupRequirement{Name: "foo"},
			Groups:      GroupRequirements{{Name: "foo"}},
		},
		opts: &EnsureOpts{
			CreateAllowed: common.P(false),
			ModifyAllowed: common.P(false),
		},

		expectedResult: EnsureResultUnchanged,
		expected:       User{"foo", "Foo Name", 1, Group{1, "foo"}, Groups{{1, "foo"}}, "/bin/foosh", "/home/foo"},
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}, {
		name: "modification-of-user-forbidden",
		requirement: Requirement{
			Name:        "foo",
			Shell:       "/bin/foosh",
			HomeDir:     "/home/foo",
			DisplayName: "Foo Names",
			Group:       GroupRequirement{Name: "foo"},
			Groups:      GroupRequirements{{Name: "foo"}},
		},
		opts: &EnsureOpts{
			ModifyAllowed: common.P(false),
		},

		expectedResult: EnsureResultError,
		expectedErr:    ErrUserDoesNotFulfilRequirement.Error(),
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}, {
		name: "modification-of-users-group-forbidden",
		requirement: Requirement{
			Name:        "foo",
			Shell:       "/bin/foosh",
			HomeDir:     "/home/foo",
			DisplayName: "Foo Name",
			Group:       GroupRequirement{Gid: common.P(GroupId(1)), Name: "foos"},
			Groups:      GroupRequirements{{Gid: common.P(GroupId(1)), Name: "foos"}},
		},
		opts: &EnsureOpts{
			ModifyAllowed: common.P(false),
		},

		expectedResult: EnsureResultError,
		expectedErr:    ErrUserDoesNotFulfilRequirement.Error(),
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}, {
		name: "creation-of-user-forbidden",
		requirement: Requirement{
			Name:        "foo2",
			Shell:       "/bin/foosh",
			HomeDir:     "/home/foo",
			DisplayName: "Foo Name",
			Group:       GroupRequirement{Name: "foo"},
			Groups:      GroupRequirements{{Name: "foo"}},
		},
		opts: &EnsureOpts{
			CreateAllowed: common.P(false),
		},

		expectedResult: EnsureResultError,
		expectedErr:    ErrNoSuchUser.Error(),
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}, {
		name: "creation-of-users-group-forbidden",
		requirement: Requirement{
			Name:        "foo",
			Shell:       "/bin/foosh",
			HomeDir:     "/home/foo",
			DisplayName: "Foo Name",
			Group:       GroupRequirement{Name: "foo2"},
			Groups:      GroupRequirements{{Name: "foo"}},
		},
		opts: &EnsureOpts{
			CreateAllowed: common.P(false),
		},

		expectedResult: EnsureResultError,
		expectedErr:    ErrNoSuchGroup.Error(),
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}, {
		name: "creation-of-users-groups-forbidden",
		requirement: Requirement{
			Name:        "foo",
			Shell:       "/bin/foosh",
			HomeDir:     "/home/foo",
			DisplayName: "Foo Name",
			Group:       GroupRequirement{Name: "foo"},
			Groups:      GroupRequirements{{Name: "foo"}, {Name: "foo2"}},
		},
		opts: &EnsureOpts{
			CreateAllowed: common.P(false),
		},

		expectedResult: EnsureResultError,
		expectedErr:    ErrNoSuchGroup.Error(),
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)
			passwdFile := dir.file("passwd").setContent(`root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`)
			groupFile := dir.file("group").setContent(`root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`)
			shadowFile := dir.file("shadow").setContent(`root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			actual, actualResult, actualErr := instance.Ensure(context.Background(), &c.requirement, c.opts)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, &c.expected, actual)
			}

			assert.Equal(t, c.expectedResult, actualResult)
			assert.Regexp(t, c.expectedPasswd, passwdFile.content())
			assert.Regexp(t, c.expectedGroup, groupFile.content())
			assert.Regexp(t, c.expectedShadow, shadowFile.content())

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
			time.Sleep(100 * time.Millisecond)
		})
	}
}

func Test_EtcColonRepository_Ensure_homeDirectory_create(t *testing.T) {
	testlog.Hook(t)

	dir := newTestDir(t)

	skel := dir.dir("skel")
	skel.file(".profile").setContent("something...").setPerms(0644)
	skelSecret := skel.dir("secret").setPerms(0700)
	skelSecret.file("key").setContent("something secret...").setPerms(0600)
	skelOther := skel.dir("other").setPerms(0755)
	skelOther.file("info").setContent("some info...").setPerms(0644)

	homeDirFn := dir.child("home-dir")

	etc := dir.dir("etc")

	var unhandledAsyncError error
	var unhandledAsyncErrorDetail string
	instance := EtcColonRepository{
		PasswdFilename: etc.file("passwd").name(),
		GroupFilename:  etc.file("group").name(),
		ShadowFilename: etc.file("shadow").name(),
		OnUnhandledAsyncError: func(_ log.Logger, err error, detail string) {
			unhandledAsyncError = err
			unhandledAsyncErrorDetail = detail
		},
	}

	require.NoError(t, instance.Init(context.Background()))

	defer func() {
		etcColonRepositoryChownFunc = os.Chown
	}()
	// Odd, but we have to do it this way otherwise the tests always requires root permissions.
	calledChowns := map[string]struct{}{}
	etcColonRepositoryChownFunc = func(name string, uid, gid int) error {
		assert.Equal(t, uid, 2)
		assert.Equal(t, gid, 3)
		calledChowns[name] = struct{}{}
		return nil
	}

	actualUser, actualResult, actualErr := instance.Ensure(context.Background(), &Requirement{
		Name:        "foo",
		DisplayName: "Foo Name",
		Uid:         common.P[Id](2),
		Group:       GroupRequirement{common.P[GroupId](3), "foo"},
		Groups:      nil,
		Shell:       "/bin/foosh",
		HomeDir:     dir.child("home-dir"),
		Skel:        skel.name(),
	}, nil)
	require.NoError(t, actualErr)
	require.Equal(t, EnsureResultCreated, actualResult)
	require.NotNil(t, actualUser)
	require.Equal(t, homeDirFn, actualUser.HomeDir)

	compare := func(left, right string) {
		assert.NoError(t, filepath.Walk(left, func(leftPath string, leftFi fs.FileInfo, err error) error {
			require.NoError(t, err)

			rel, err := filepath.Rel(left, leftPath)
			require.NoError(t, err)
			rightPath := filepath.Join(right, rel)

			rightFi, err := os.Stat(rightPath)
			require.NoError(t, err)

			assert.Equal(t, leftFi.Mode(), rightFi.Mode())
			assert.Equal(t, leftFi.IsDir(), rightFi.IsDir())
			assert.Equal(t, leftFi.Size(), rightFi.Size())
			assert.Equal(t, leftFi.ModTime(), rightFi.ModTime())
			if !leftFi.IsDir() {
				leftContent := (&testFile{t, dir, leftPath}).content()
				rightContent := (&testFile{t, dir, rightPath}).content()
				assert.Equal(t, leftContent, rightContent)
			}

			log.Info(leftPath, rightPath)
			return nil
		}))
	}
	compare(skel.name(), homeDirFn)
	compare(homeDirFn, skel.name())

	notAlreadyCheckedChowns := maps.Clone(calledChowns)
	assert.NoError(t, filepath.Walk(homeDirFn, func(path string, fi fs.FileInfo, err error) error {
		require.NoError(t, err)

		_, chownHappened := notAlreadyCheckedChowns[path]
		assert.Equal(t, true, chownHappened)
		delete(notAlreadyCheckedChowns, path)
		return nil
	}))

	assert.Len(t, notAlreadyCheckedChowns, 0)

	assert.NoError(t, instance.Close())
	assert.NoError(t, unhandledAsyncError)
	assert.Empty(t, unhandledAsyncErrorDetail)
}

func Test_EtcColonRepository_Ensure_homeDirectory_move(t *testing.T) {
	testlog.Hook(t)

	dir := newTestDir(t)

	oldHd := dir.dir("old")
	oldHd.file(".profile").setContent("something...").setPerms(0644)
	oldHdSecret := oldHd.dir("secret").setPerms(0700)
	oldHdSecret.file("key").setContent("something secret...").setPerms(0600)
	oldHdOther := oldHd.dir("other").setPerms(0755)
	oldHdOther.file("info").setContent("some info...").setPerms(0644)

	newHd := dir.child("new")

	etc := dir.dir("etc")

	var unhandledAsyncError error
	var unhandledAsyncErrorDetail string
	instance := EtcColonRepository{
		PasswdFilename: etc.file("passwd").setContent(`foo:abc:1:2:Foo Name:` + oldHd.name() + `:/bin/foosh`).name(),
		GroupFilename:  etc.file("group").setContent("g2:x:2:\ng4:x:4:").name(),
		ShadowFilename: etc.file("shadow").setContent("foo:x:19722:10:100::::").name(),
		OnUnhandledAsyncError: func(_ log.Logger, err error, detail string) {
			unhandledAsyncError = err
			unhandledAsyncErrorDetail = detail
		},
	}

	require.NoError(t, instance.Init(context.Background()))

	defer func() {
		etcColonRepositoryChownFunc = os.Chown
	}()
	// Odd, but we have to do it this way otherwise the tests always requires root permissions.
	calledChowns := map[string]struct{}{}
	etcColonRepositoryChownFunc = func(name string, uid, gid int) error {
		assert.Equal(t, uid, 3)
		assert.Equal(t, gid, 4)
		calledChowns[name] = struct{}{}
		return nil
	}

	actualUser, actualResult, actualErr := instance.Ensure(context.Background(), &Requirement{
		Name:        "foo",
		DisplayName: "Foo Name",
		Uid:         common.P[Id](3),
		Group:       GroupRequirement{common.P[GroupId](4), "foo"},
		Groups:      nil,
		Shell:       "/bin/foosh",
		HomeDir:     newHd,
		Skel:        "/foo",
	}, nil)
	require.NoError(t, actualErr)
	require.Equal(t, EnsureResultModified, actualResult)
	require.NotNil(t, actualUser)
	require.Equal(t, newHd, actualUser.HomeDir)

	notAlreadyCheckedChowns := maps.Clone(calledChowns)
	assert.NoError(t, filepath.Walk(newHd, func(path string, fi fs.FileInfo, err error) error {
		require.NoError(t, err)

		_, chownHappened := notAlreadyCheckedChowns[path]
		assert.Equal(t, true, chownHappened)
		delete(notAlreadyCheckedChowns, path)
		return nil
	}))

	assert.Len(t, notAlreadyCheckedChowns, 0)

	assert.NoError(t, instance.Close())
	assert.NoError(t, unhandledAsyncError)
	assert.Empty(t, unhandledAsyncErrorDetail)
}

func Test_EtcColonRepository_DeleteById(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name      string
		givenId   Id
		givenOpts DeleteOpts

		expectedPasswd string
		expectedGroup  string
		expectedShadow string

		expectedErr string
	}{{
		name:    "ok",
		givenId: 1,
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
bar::11:12::/home/bar:/bin/barsh
$`,
		expectedGroup: `^root:x:0:
foo:abc:1:bbb
bar::12:bar
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
bar:XbarX:20453:10:100:::20818:
$`,
	}, {
		name:    "does-not-exist",
		givenId: 2,

		expectedErr: ErrNoSuchUser.Error(),
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)
			passwdFile := dir.file("passwd").setContent(`root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`)
			groupFile := dir.file("group").setContent(`root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`)
			shadowFile := dir.file("shadow").setContent(`root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			actualErr = instance.DeleteById(context.Background(), c.givenId, &c.givenOpts)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
			}

			assert.Regexp(t, c.expectedPasswd, passwdFile.content())
			assert.Regexp(t, c.expectedGroup, groupFile.content())
			assert.Regexp(t, c.expectedShadow, shadowFile.content())

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
		})
	}
}

func Test_EtcColonRepository_DeleteByName(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name      string
		givenName string
		givenOpts DeleteOpts

		expectedPasswd string
		expectedGroup  string
		expectedShadow string

		expectedErr string
	}{{
		name:      "ok",
		givenName: "foo",
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
bar::11:12::/home/bar:/bin/barsh
$`,
		expectedGroup: `^root:x:0:
foo:abc:1:bbb
bar::12:bar
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
bar:XbarX:20453:10:100:::20818:
$`,
	}, {
		name:      "does-not-exist",
		givenName: "foo2",

		expectedErr: ErrNoSuchUser.Error(),
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)
			passwdFile := dir.file("passwd").setContent(`root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`)
			groupFile := dir.file("group").setContent(`root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`)
			shadowFile := dir.file("shadow").setContent(`root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			actualErr = instance.DeleteByName(context.Background(), c.givenName, &c.givenOpts)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
			}

			assert.Regexp(t, c.expectedPasswd, passwdFile.content())
			assert.Regexp(t, c.expectedGroup, groupFile.content())
			assert.Regexp(t, c.expectedShadow, shadowFile.content())

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
		})
	}
}

func Test_EtcColonRepository_ValidatePasswordById(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name          string
		givenId       Id
		givenPassword string

		expected    bool
		expectedErr string
	}{{
		name: "match",

		givenId:       1,
		givenPassword: "foobar",

		expected: true,
	}, {
		name:          "mismatch",
		givenId:       1,
		givenPassword: "foobar-wrong",

		expected: false,
	}, {
		name:    "does-not-exist",
		givenId: 2,

		expected:    false,
		expectedErr: ErrNoSuchUser.Error(),
	}, {
		name:          "expired-thresholds",
		givenId:       3,
		givenPassword: "foobar",

		expected: false,
	}, {
		name:          "expired-ts",
		givenId:       4,
		givenPassword: "foobar",

		expected: false,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)
			passwdFile := dir.file("passwd").setContent(`root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh
expired:abc:3:1::/bin/false:/bin/false
expired-ts:abc:4:1::/bin/false:/bin/false`)
			groupFile := dir.file("group").setContent(`root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`)
			shadowFile := dir.file("shadow").setContent(`root:XrootX:19722:10:100:50:200:20088:
foo:$y$j9T$as2ASyXW241FbtyMlNNQU1$sy6H9k6uXgaY1DeIKI5zPVsczWLD82k5UeQVuIMuhuB:20088:10:100::::
bar:XbarX:20453:10:100:::20818:
expired:$y$j9T$as2ASyXW241FbtyMlNNQU1$sy6H9k6uXgaY1DeIKI5zPVsczWLD82k5UeQVuIMuhuB:19931:1:10::5::
expired-ts:$y$j9T$as2ASyXW241FbtyMlNNQU1$sy6H9k6uXgaY1DeIKI5zPVsczWLD82k5UeQVuIMuhuB:19931:1:10:::19931:`)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			actual, actualErr := instance.ValidatePasswordById(context.Background(), c.givenId, c.givenPassword)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				assert.Equal(t, c.expected, actual)
			}

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
			time.Sleep(150 * time.Millisecond)
		})
	}
}

func Test_EtcColonRepository_ValidatePasswordById_withoutShadow(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name          string
		givenId       Id
		givenPassword string

		expected    bool
		expectedErr string
	}{{
		name: "match",

		givenId:       1,
		givenPassword: "abc",

		expected: true,
	}, {
		name:          "mismatch",
		givenId:       1,
		givenPassword: "abc-wrong",

		expected: false,
	}, {
		name:    "does-not-exist",
		givenId: 2,

		expected:    false,
		expectedErr: ErrNoSuchUser.Error(),
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)
			passwdFile := dir.file("passwd").setContent(`root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`)
			groupFile := dir.file("group").setContent(`root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`)
			shadowFile := dir.file("shadow").setContent(`root:XrootX:19722:10:100:50:200:20088:
bar:XbarX:20453:10:100:::20818:`)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			actual, actualErr := instance.ValidatePasswordById(context.Background(), c.givenId, c.givenPassword)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				assert.Equal(t, c.expected, actual)
			}

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
		})
	}
}

func Test_EtcColonRepository_ValidatePasswordByName(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name          string
		givenName     string
		givenPassword string

		expected    bool
		expectedErr string
	}{{
		name: "match",

		givenName:     "foo",
		givenPassword: "foobar",

		expected: true,
	}, {
		name:          "mismatch",
		givenName:     "foo",
		givenPassword: "foobar-wrong",

		expected: false,
	}, {
		name:      "does-not-exist",
		givenName: "foo2",

		expected:    false,
		expectedErr: ErrNoSuchUser.Error(),
	}, {
		name:          "expired-thresholds",
		givenName:     "expired",
		givenPassword: "foobar",

		expected: false,
	}, {
		name:          "expired-ts",
		givenName:     "expired-ts",
		givenPassword: "foobar",

		expected: false,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)
			passwdFile := dir.file("passwd").setContent(`root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh
expired:abc:3:1::/bin/false:/bin/false
expired-ts:abc:4:1::/bin/false:/bin/false`)
			groupFile := dir.file("group").setContent(`root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`)
			shadowFile := dir.file("shadow").setContent(`root:XrootX:19722:10:100:50:200:20088:
foo:$y$j9T$as2ASyXW241FbtyMlNNQU1$sy6H9k6uXgaY1DeIKI5zPVsczWLD82k5UeQVuIMuhuB:20088:10:100::::
bar:XbarX:20453:10:100:::20818:
expired:$y$j9T$as2ASyXW241FbtyMlNNQU1$sy6H9k6uXgaY1DeIKI5zPVsczWLD82k5UeQVuIMuhuB:19931:1:10::5::
expired:$y$j9T$as2ASyXW241FbtyMlNNQU1$sy6H9k6uXgaY1DeIKI5zPVsczWLD82k5UeQVuIMuhuB:19931:1:10:::19931:`)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			actual, actualErr := instance.ValidatePasswordByName(context.Background(), c.givenName, c.givenPassword)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				assert.Equal(t, c.expected, actual)
			}

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
		})
	}
}

func Test_EtcColonRepository_ValidatePasswordByName_withoutShadow(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name          string
		givenName     string
		givenPassword string

		expected    bool
		expectedErr string
	}{{
		name: "match",

		givenName:     "foo",
		givenPassword: "abc",

		expected: true,
	}, {
		name:          "mismatch",
		givenName:     "foo",
		givenPassword: "abc-wrong",

		expected: false,
	}, {
		name:      "does-not-exist",
		givenName: "foo2",

		expected:    false,
		expectedErr: ErrNoSuchUser.Error(),
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)
			passwdFile := dir.file("passwd").setContent(`root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`)
			groupFile := dir.file("group").setContent(`root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`)
			shadowFile := dir.file("shadow").setContent(`root:XrootX:19722:10:100:50:200:20088:
bar:XbarX:20453:10:100:::20818:`)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			actual, actualErr := instance.ValidatePasswordByName(context.Background(), c.givenName, c.givenPassword)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				assert.Equal(t, c.expected, actual)
			}

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
		})
	}
}

func Test_EtcColonRepository_EnsureGroup(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name        string
		requirement GroupRequirement
		opts        *EnsureOpts

		expected       Group
		expectedGroup  string
		expectedResult EnsureResult

		expectedErr string
	}{{
		name: "full-create",
		requirement: GroupRequirement{
			Gid:  common.P[GroupId](666),
			Name: "x666x",
		},

		expected:       Group{666, "x666x"},
		expectedResult: EnsureResultCreated,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
x666x:x:666:
$`,
	}, {
		name: "create-forbidden",
		requirement: GroupRequirement{
			Gid:  common.P[GroupId](666),
			Name: "x666x",
		},
		opts: &EnsureOpts{
			CreateAllowed: common.P(false),
		},

		expectedErr:    ErrNoSuchGroup.Error(),
		expectedResult: EnsureResultError,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar$`,
	}, {
		name: "create-but-generate-id",
		requirement: GroupRequirement{
			Name: "x1000x",
		},

		expected:       Group{1000, "x1000x"},
		expectedResult: EnsureResultCreated,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
x1000x:x:1000:
$`,
	}, {
		name: "create-but-generate-name",
		requirement: GroupRequirement{
			Gid: common.P[GroupId](666),
		},

		expected:       Group{666, "g666"},
		expectedResult: EnsureResultCreated,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
g666:x:666:
$`,
	}, {
		name: "update-name",
		requirement: GroupRequirement{
			Gid:  common.P[GroupId](1),
			Name: "foo2",
		},

		expected:       Group{1, "foo2"},
		expectedResult: EnsureResultModified,
		expectedGroup: `^root:x:0:
foo2:abc:1:foo,bbb
bar::12:bar
$`,
	}, {
		name: "update-id",
		requirement: GroupRequirement{
			Gid:  common.P[GroupId](2),
			Name: "foo",
		},

		expected:       Group{2, "foo"},
		expectedResult: EnsureResultModified,
		expectedGroup: `^root:x:0:
foo:abc:2:foo,bbb
bar::12:bar
$`,
	}, {
		name: "modification-forbidden",
		requirement: GroupRequirement{
			Gid:  common.P[GroupId](1),
			Name: "foo2",
		},
		opts: &EnsureOpts{
			ModifyAllowed: common.P(false),
		},

		expectedErr:    ErrGroupDoesNotFulfilRequirement.Error(),
		expectedResult: EnsureResultError,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar$`,
	}, {
		name: "unchanged",
		requirement: GroupRequirement{
			Gid:  common.P[GroupId](1),
			Name: "foo",
		},

		expected:       Group{1, "foo"},
		expectedResult: EnsureResultUnchanged,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar$`,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)

			givenPasswdContent := `root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`
			passwdFile := dir.file("passwd").setContent(givenPasswdContent)
			groupFile := dir.file("group").setContent(`root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`)
			givenShadowContent := `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`
			shadowFile := dir.file("shadow").setContent(givenShadowContent)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			actual, actualResult, actualErr := instance.EnsureGroup(context.Background(), &c.requirement, c.opts)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, &c.expected, actual)
			}

			assert.Equal(t, c.expectedResult, actualResult)
			assert.Regexp(t, givenPasswdContent, passwdFile.content())
			assert.Regexp(t, c.expectedGroup, groupFile.content())
			assert.Regexp(t, givenShadowContent, shadowFile.content())

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
		})
	}
}

func Test_EtcColonRepository_DeleteGroupById(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name      string
		givenId   GroupId
		givenOpts DeleteOpts

		expectedPasswd string
		expectedGroup  string
		expectedShadow string

		expectedErr string
	}{{
		name:    "ok",
		givenId: 2,
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh
$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
foo3::3:foo,bbb
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:
$`,
	}, {
		name:    "does-not-exist",
		givenId: 4,

		expectedErr: ErrNoSuchGroup.Error(),
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
foo2::2:foo,bbb
foo3::3:foo,bbb
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}, {
		name:    "still-in-use",
		givenId: 1,

		expectedErr: "cannot delete group because it is still used by user 1(foo)",
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
foo2::2:foo,bbb
foo3::3:foo,bbb
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)

			passwdFile := dir.file("passwd").setContent(`root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`)
			groupFile := dir.file("group").setContent(`root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
foo2::2:foo,bbb
foo3::3:foo,bbb
`)
			shadowFile := dir.file("shadow").setContent(`root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			actualErr = instance.DeleteGroupById(context.Background(), c.givenId, &c.givenOpts)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
			}

			assert.Regexp(t, c.expectedPasswd, passwdFile.content())
			assert.Regexp(t, c.expectedGroup, groupFile.content())
			assert.Regexp(t, c.expectedShadow, shadowFile.content())

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
		})
	}
}

func Test_EtcColonRepository_DeleteGroupByName(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name      string
		givenName string
		givenOpts DeleteOpts

		expectedPasswd string
		expectedGroup  string
		expectedShadow string

		expectedErr string
	}{{
		name:      "ok",
		givenName: "foo2",
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh
$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
foo3::3:foo,bbb
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:
$`,
	}, {
		name:      "does-not-exist",
		givenName: "foo4",

		expectedErr: ErrNoSuchGroup.Error(),
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
foo2::2:foo,bbb
foo3::3:foo,bbb
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}, {
		name:      "still-in-use",
		givenName: "foo",

		expectedErr: "cannot delete group because it is still used by user 1(foo)",
		expectedPasswd: `^root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh$`,
		expectedGroup: `^root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
foo2::2:foo,bbb
foo3::3:foo,bbb
$`,
		expectedShadow: `^root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:$`,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)

			passwdFile := dir.file("passwd").setContent(`root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`)
			groupFile := dir.file("group").setContent(`root:x:0:
foo:abc:1:foo,bbb
bar::12:bar
foo2::2:foo,bbb
foo3::3:foo,bbb
`)
			shadowFile := dir.file("shadow").setContent(`root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			actualErr = instance.DeleteGroupByName(context.Background(), c.givenName, &c.givenOpts)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
			}

			assert.Regexp(t, c.expectedPasswd, passwdFile.content())
			assert.Regexp(t, c.expectedGroup, groupFile.content())
			assert.Regexp(t, c.expectedShadow, shadowFile.content())

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
		})
	}
}

func TestEtcColonRepository_onUnhandledAsyncError_default(t *testing.T) {
	genericError := errors.New("foobar1")
	stringError := StringError("foobar2")

	cases := []struct {
		name        string
		givenError  error
		givenDetail string

		expectedError error
		expectedMsg   string
	}{{
		name: "prefix-only",

		givenDetail: "foo",

		expectedError: nil,
		expectedMsg:   "foo; will exit now to and hope for a restart of this service to reset the state (exit code 17)",
	}, {
		name: "prefix-and-generic-error",

		givenDetail: "foo",
		givenError:  genericError,

		expectedError: genericError,
		expectedMsg:   "foo; will exit now to and hope for a restart of this service to reset the state (exit code 17)",
	}, {
		name: "generic-error-only",

		givenError: genericError,

		expectedError: genericError,
		expectedMsg:   "unexpected error; will exit now to and hope for a restart of this service to reset the state (exit code 17)",
	}, {
		name: "prefix-and-string-error",

		givenDetail: "foo",
		givenError:  stringError,

		expectedError: stringError,
		expectedMsg:   "foo; will exit now to and hope for a restart of this service to reset the state (exit code 17)",
	}, {
		name: "string-error-only",

		givenError: stringError,

		expectedError: nil,
		expectedMsg:   "foobar2; will exit now to and hope for a restart of this service to reset the state (exit code 17)",
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			givenLogger := recording.NewLogger()

			oldFunc := etcColonRepositoryExitFunc
			defer func() { etcColonRepositoryExitFunc = oldFunc }()
			exitFuncCalled := false
			etcColonRepositoryExitFunc = func() { exitFuncCalled = true }

			instance := &EtcColonRepository{}
			instance.onUnhandledAsyncError(givenLogger, c.givenError, c.givenDetail)

			assert.Equal(t, true, exitFuncCalled, c.expectedMsg)
			require.Equal(t, 1, givenLogger.Len())

			actualEvent := givenLogger.Get(0)
			assert.Equal(t, level.Fatal, actualEvent.GetLevel())

			actualMessage, _ := actualEvent.Get("message")
			assert.Equal(t, c.expectedMsg, actualMessage)

			actualError, _ := actualEvent.Get("error")
			assert.Equal(t, c.expectedError, actualError)
		})
	}
}

func TestEtcColonRepository_onUnhandledAsyncError_custom(t *testing.T) {
	givenLogger := recording.NewLogger()
	givenError := errors.New("foobar")
	givenDetail := "666"

	methodCalled := false
	instance := &EtcColonRepository{
		OnUnhandledAsyncError: func(actualLogger log.Logger, actualError error, actualDetail string) {
			assert.Equal(t, givenLogger, actualLogger)
			assert.Equal(t, givenError, actualError)
			assert.Equal(t, givenDetail, actualDetail)
			methodCalled = true
		},
	}
	instance.onUnhandledAsyncError(givenLogger, givenError, givenDetail)

	assert.Equal(t, true, methodCalled)
}

func TestEtcColonRepository_LookupByName(t *testing.T) {
	cases := []struct {
		name        string
		givenName   string
		givenPasswd string
		givenGroup  string
		givenShadow string

		hook func(*EtcColonRepository)

		expected    User
		expectedErr string
	}{{
		name: "single-group",

		givenName: "foo",
		givenPasswd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
		givenGroup: `root:x:0:
foo:abc:1:bbb
bar::12:bar`,
		givenShadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,

		expected: User{"foo", "Foo Name", 1, Group{1, "foo"}, nil, "/bin/foosh", "/home/foo"},
	}, {
		name: "group-and-groups",

		givenName: "foo",
		givenPasswd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
		givenGroup: `root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`,
		givenShadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,

		expected: User{"foo", "Foo Name", 1, Group{1, "foo"}, Groups{{1, "foo"}}, "/bin/foosh", "/home/foo"},
	}, {
		name: "no-such-user",

		givenName: "foos",
		givenPasswd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
		givenGroup: `root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`,
		givenShadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,

		expectedErr: ErrNoSuchUser.Error(),
	}, {
		name: "non-existing-group",

		givenName: "foo",
		givenPasswd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
		givenGroup: `root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`,
		givenShadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,

		expected: User{"foo", "Foo Name", 1, Group{2, "g2"}, Groups{{1, "foo"}}, "/bin/foosh", "/home/foo"},
	}, {
		name: "non-existing-groups",

		givenName: "foo",
		givenPasswd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
		givenGroup: `root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`,
		givenShadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,

		hook: func(instance *EtcColonRepository) {
			instance.usernameToGroups["foo"] = append(instance.usernameToGroups["foo"], &etcGroupRef{&etcGroupEntry{gid: 666}})
		},

		expected: User{"foo", "Foo Name", 1, Group{1, "foo"}, Groups{{1, "foo"}, {666, ""}}, "/bin/foosh", "/home/foo"},
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)
			passwdFile := dir.file("passwd").setContent(c.givenPasswd)
			groupFile := dir.file("group").setContent(c.givenGroup)
			shadowFile := dir.file("shadow").setContent(c.givenShadow)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			if h := c.hook; h != nil {
				h(&instance)
			}

			actual, actualErr := instance.LookupByName(context.Background(), c.givenName)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, &c.expected, actual)
			}

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
		})
	}
}

func TestEtcColonRepository_LookupByName_uninitialized(t *testing.T) {
	instance := EtcColonRepository{}

	actual, actualErr := instance.LookupByName(context.Background(), "foo")
	assert.Nil(t, actual)
	assert.Equal(t, ErrNoSuchUser, actualErr)
}

func TestEtcColonRepository_LookupById(t *testing.T) {
	cases := []struct {
		name        string
		givenId     Id
		givenPasswd string
		givenGroup  string
		givenShadow string

		hook func(*EtcColonRepository)

		expected    User
		expectedErr string
	}{{
		name: "single-group",

		givenId: 1,
		givenPasswd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
		givenGroup: `root:x:0:
foo:abc:1:bbb
bar::12:bar`,
		givenShadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,

		expected: User{"foo", "Foo Name", 1, Group{1, "foo"}, nil, "/bin/foosh", "/home/foo"},
	}, {
		name: "group-and-groups",

		givenId: 1,
		givenPasswd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
		givenGroup: `root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`,
		givenShadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,

		expected: User{"foo", "Foo Name", 1, Group{1, "foo"}, Groups{{1, "foo"}}, "/bin/foosh", "/home/foo"},
	}, {
		name: "no-such-user",

		givenId: 666,
		givenPasswd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
		givenGroup: `root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`,
		givenShadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,

		expectedErr: ErrNoSuchUser.Error(),
	}, {
		name: "non-existing-group",

		givenId: 1,
		givenPasswd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:2:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
		givenGroup: `root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`,
		givenShadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,

		expected: User{"foo", "Foo Name", 1, Group{2, "g2"}, Groups{{1, "foo"}}, "/bin/foosh", "/home/foo"},
	}, {
		name: "non-existing-groups",

		givenId: 1,
		givenPasswd: `root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`,
		givenGroup: `root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`,
		givenShadow: `root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`,

		hook: func(instance *EtcColonRepository) {
			instance.usernameToGroups["foo"] = append(instance.usernameToGroups["foo"], &etcGroupRef{&etcGroupEntry{gid: 666}})
		},

		expected: User{"foo", "Foo Name", 1, Group{1, "foo"}, Groups{{1, "foo"}, {666, ""}}, "/bin/foosh", "/home/foo"},
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)
			passwdFile := dir.file("passwd").setContent(c.givenPasswd)
			groupFile := dir.file("group").setContent(c.givenGroup)
			shadowFile := dir.file("shadow").setContent(c.givenShadow)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			if h := c.hook; h != nil {
				h(&instance)
			}

			actual, actualErr := instance.LookupById(context.Background(), c.givenId)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, &c.expected, actual)
			}

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
		})
	}
}

func TestEtcColonRepository_LookupById_uninitialized(t *testing.T) {
	instance := EtcColonRepository{}

	actual, actualErr := instance.LookupById(context.Background(), 1)
	assert.Nil(t, actual)
	assert.Equal(t, ErrNoSuchUser, actualErr)
}

func TestEtcColonRepository_LookupGroupByName(t *testing.T) {
	cases := []struct {
		name       string
		givenName  string
		givenGroup string

		expected    Group
		expectedErr string
	}{{
		name: "single",

		givenName: "foo",
		givenGroup: `root:x:0:
foo:abc:1:bbb
bar::12:bar`,

		expected: Group{1, "foo"},
	}, {
		name: "no-such-group",

		givenName: "other",
		givenGroup: `root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`,

		expectedErr: ErrNoSuchGroup.Error(),
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)
			passwdFile := dir.file("passwd").setContent(`root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`)
			groupFile := dir.file("group").setContent(c.givenGroup)
			shadowFile := dir.file("shadow").setContent(`root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			actual, actualErr := instance.LookupGroupByName(context.Background(), c.givenName)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, &c.expected, actual)
			}

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
		})
	}
}

func TestEtcColonRepository_LookupGroupByName_uninitialized(t *testing.T) {
	instance := EtcColonRepository{}

	actual, actualErr := instance.LookupGroupByName(context.Background(), "foo")
	assert.Nil(t, actual)
	assert.Equal(t, ErrNoSuchGroup, actualErr)
}

func TestEtcColonRepository_LookupGroupById(t *testing.T) {
	cases := []struct {
		name       string
		givenId    GroupId
		givenGroup string

		expected    Group
		expectedErr string
	}{{
		name: "single",

		givenId: 1,
		givenGroup: `root:x:0:
foo:abc:1:bbb
bar::12:bar`,

		expected: Group{1, "foo"},
	}, {
		name: "no-such-group",

		givenId: 666,
		givenGroup: `root:x:0:
foo:abc:1:foo,bbb
bar::12:bar`,

		expectedErr: ErrNoSuchGroup.Error(),
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newTestDir(t)
			passwdFile := dir.file("passwd").setContent(`root:x:0:0:root:/root:/bin/sh
foo:abc:1:1:Foo Name:/home/foo:/bin/foosh
bar::11:12::/home/bar:/bin/barsh`)
			groupFile := dir.file("group").setContent(c.givenGroup)
			shadowFile := dir.file("shadow").setContent(`root:XrootX:19722:10:100:50:200:20088:
foo:XfooX:20088:10:100::::
bar:XbarX:20453:10:100:::20818:`)

			var syncError error
			instance := EtcColonRepository{
				PasswdFilename: passwdFile.name(),
				GroupFilename:  groupFile.name(),
				ShadowFilename: shadowFile.name(),
				OnUnhandledAsyncError: func(logger log.Logger, err error, detail string) {
					syncError = err
				},
			}

			actualErr := instance.Init(context.Background())
			require.NoError(t, actualErr)

			actual, actualErr := instance.LookupGroupById(context.Background(), c.givenId)
			if expectedErr := c.expectedErr; expectedErr != "" {
				assert.ErrorContains(t, actualErr, expectedErr)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, &c.expected, actual)
			}

			actualErr = instance.Close()
			require.NoError(t, actualErr)

			assert.NoError(t, syncError)
		})
	}
}

func TestEtcColonRepository_LookupGroupById_uninitialized(t *testing.T) {
	instance := EtcColonRepository{}

	actual, actualErr := instance.LookupGroupById(context.Background(), 1)
	assert.Nil(t, actual)
	assert.Equal(t, ErrNoSuchGroup, actualErr)
}
