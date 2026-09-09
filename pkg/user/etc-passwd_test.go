//go:build unix

package user

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/echocat/slf4g/sdk/testlog"
	"github.com/stretchr/testify/require"
)

func TestEtcPasswdEntriesPreserveDataBeyondScannerBuffer(t *testing.T) {
	var content strings.Builder
	for i := range 100 {
		_, err := fmt.Fprintf(
			&content,
			"test%d:x:%d:1000:Test User %d with a sufficiently long display name:/home/test%d:/bin/sh\n",
			i,
			10000+i,
			i,
			i,
		)
		require.NoError(t, err)
	}
	require.Greater(t, content.Len(), 4096)

	path := filepath.Join(t.TempDir(), "passwd")
	require.NoError(t, os.WriteFile(path, []byte(content.String()), 0600))
	source, err := os.Open(path)
	require.NoError(t, err)

	var entries etcColonEntries[etcPasswdEntry, *etcPasswdEntry]
	require.NoError(t, entries.decode(etcPasswdColons, false, false, source))
	require.NoError(t, source.Close())
	require.Len(t, entries, 100)
	for i, entry := range entries {
		require.Equal(t, fmt.Sprintf("test%d", i), string(entry.entry.name))
		require.Equal(t, fmt.Sprintf("Test User %d with a sufficiently long display name", i), string(entry.entry.geocs))
	}

	target, err := os.Create(filepath.Join(t.TempDir(), "encoded-passwd"))
	require.NoError(t, err)
	require.NoError(t, entries.encode(false, target))
	_, err = target.Seek(0, io.SeekStart)
	require.NoError(t, err)
	actual, err := io.ReadAll(target)
	require.NoError(t, err)
	require.NoError(t, target.Close())
	require.Equal(t, content.String(), string(actual))
}

func Test_etcPasswdEntry_decode(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name         string
		given        [][]byte
		allowBadName bool
		expected     etcPasswdEntry
		expectedErr  string
	}{{
		name:         "simple",
		given:        bs("root", "x", "1", "2", "The Root", "/root", "/bin/sh"),
		allowBadName: false,
		expected:     etcPasswdEntry{b("root"), b("x"), 1, 2, b("The Root"), b("/root"), b("/bin/sh")},
	}, {
		name:         "forbidden-bad-name",
		given:        bs("root@", "x", "0", "0", "root", "/root", "/bin/sh"),
		allowBadName: false,
		expectedErr:  "illegal user name",
	}, {
		name:         "allowed-bad-name",
		given:        bs("root@", "x", "0", "0", "root", "/root", "/bin/sh"),
		allowBadName: true,
		expected:     etcPasswdEntry{b("root@"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")},
	}, {
		name:         "empty-user-name",
		given:        bs("", "x", "0", "0", "root", "/root", "/bin/sh"),
		allowBadName: false,
		expectedErr:  "empty user name",
	}, {
		name:         "illegal-user-name",
		given:        bs("ro\tot", "x", "0", "0", "root", "/root", "/bin/sh"),
		allowBadName: true,
		expectedErr:  "illegal user name",
	}, {
		name:         "too-long-user-name",
		given:        bs("a012345678901234567890123456789012", "x", "0", "0", "root", "/root", "/bin/sh"),
		allowBadName: true,
		expectedErr:  "user name is longer than 32 characters",
	}, {
		name:         "empty-uid",
		given:        bs("root", "x", "", "0", "root", "/root", "/bin/sh"),
		allowBadName: true,
		expectedErr:  "empty UID",
	}, {
		name:         "illegal-uid",
		given:        bs("root", "x", "-0", "0", "root", "/root", "/bin/sh"),
		allowBadName: true,
		expectedErr:  "illegal UID",
	}, {
		name:         "empty-gid",
		given:        bs("root", "x", "0", "", "root", "/root", "/bin/sh"),
		allowBadName: true,
		expectedErr:  "empty GID",
	}, {
		name:         "illegal-gid",
		given:        bs("root", "x", "0", "-0", "root", "/root", "/bin/sh"),
		allowBadName: true,
		expectedErr:  "illegal GID",
	}, {
		name:         "too-long-geocs",
		given:        bs("root", "x", "0", "0", "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789", "/root", "/bin/sh"),
		allowBadName: true,
		expectedErr:  "geocs is longer than 255 characters",
	}, {
		name:         "empty-home",
		given:        bs("root", "x", "0", "0", "root", "", "/bin/sh"),
		allowBadName: true,
		expectedErr:  "empty home directory",
	}, {
		name:         "too-long-home",
		given:        bs("root", "x", "0", "0", "root", "/012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789", "/bin/sh"),
		allowBadName: true,
		expectedErr:  "home directory is longer than 255 characters",
	}, {
		name:         "illegal-home",
		given:        bs("root", "x", "0", "0", "root", "/ro\000ot", "/bin/sh"),
		allowBadName: true,
		expectedErr:  "illegal home directory",
	}, {
		name:         "empty-shell",
		given:        bs("root", "x", "0", "0", "root", "/root", ""),
		allowBadName: true,
		expectedErr:  "empty shell",
	}, {
		name:         "too-long-shell",
		given:        bs("root", "x", "0", "0", "root", "/root", "/012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"),
		allowBadName: true,
		expectedErr:  "shell is longer than 255 characters",
	}, {
		name:         "illegal-shell",
		given:        bs("root", "x", "0", "0", "root", "/root", "/bi\000n/sh"),
		allowBadName: true,
		expectedErr:  "illegal shell",
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var actual etcPasswdEntry
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

func Test_etcPasswdEntry_encode(t *testing.T) {
	testlog.Hook(t)

	cases := []struct {
		name         string
		given        etcPasswdEntry
		allowBadName bool
		expected     [][]byte
		expectedErr  string
	}{{
		name:         "simple",
		given:        etcPasswdEntry{b("root"), b("x"), 1, 2, b("The Root"), b("/root"), b("/bin/sh")},
		allowBadName: false,
		expected:     bs("root", "x", "1", "2", "The Root", "/root", "/bin/sh"),
	}, {
		name:         "forbidden-bad-name",
		given:        etcPasswdEntry{b("root@"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")},
		allowBadName: false,
		expectedErr:  "illegal user name",
	}, {
		name:         "allowed-bad-name",
		given:        etcPasswdEntry{b("root@"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")},
		allowBadName: true,
		expected:     bs("root@", "x", "0", "0", "root", "/root", "/bin/sh"),
	}, {
		name:         "empty-user-name",
		given:        etcPasswdEntry{b(""), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")},
		allowBadName: false,
		expectedErr:  "empty user name",
	}, {
		name:         "illegal-user-name",
		given:        etcPasswdEntry{b("ro\tot"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")},
		allowBadName: true,
		expectedErr:  "illegal user name",
	}, {
		name:         "too-long-user-name",
		given:        etcPasswdEntry{b("a012345678901234567890123456789012"), b("x"), 0, 0, b("root"), b("/root"), b("/bin/sh")},
		allowBadName: true,
		expectedErr:  "user name is longer than 32 characters",
	}, {
		name:         "too-long-geocs",
		given:        etcPasswdEntry{b("root"), b("x"), 0, 0, b("012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"), b("/root"), b("/bin/sh")},
		allowBadName: true,
		expectedErr:  "geocs is longer than 255 characters",
	}, {
		name:         "too-long-geocs",
		given:        etcPasswdEntry{b("root"), b("x"), 0, 0, b("ro\000ot"), b("/root"), b("/bin/sh")},
		allowBadName: true,
		expectedErr:  "illegal geocs",
	}, {
		name:         "empty-home",
		given:        etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b(""), b("/bin/sh")},
		allowBadName: true,
		expectedErr:  "empty home directory",
	}, {
		name:         "too-long-home",
		given:        etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"), b("/bin/sh")},
		allowBadName: true,
		expectedErr:  "home directory is longer than 255 characters",
	}, {
		name:         "illegal-home",
		given:        etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/ro\000ot"), b("/bin/sh")},
		expected:     bs("root", "x", "0", "0", "root", "/ro\000ot", "/bin/sh"),
		allowBadName: true,
		expectedErr:  "illegal home directory",
	}, {
		name:         "empty-shell",
		given:        etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("")},
		allowBadName: true,
		expectedErr:  "empty shell",
	}, {
		name:         "too-long-shell",
		given:        etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789")},
		allowBadName: true,
		expectedErr:  "shell is longer than 255 characters",
	}, {
		name:         "illegal-shell",
		given:        etcPasswdEntry{b("root"), b("x"), 0, 0, b("root"), b("/root"), b("/b\000in/bash")},
		allowBadName: true,
		expectedErr:  "illegal shell",
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
