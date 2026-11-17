//go:build unix && !darwin

package user

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/echocat/slf4g/sdk/testlog"
	"github.com/stretchr/testify/require"
)

func newPasswordPolicyFixture(t *testing.T) (*EtcColonRepository, string) {
	t.Helper()
	testlog.Hook(t)
	root := t.TempDir()
	today := time.Now().Unix() / (24 * 60 * 60)
	shadow := fmt.Sprintf("alice:$6$fixture$%s:%d:0:99999::::\n", strings.Repeat("A", 86), today-10)
	for name, value := range map[string]string{
		"passwd": "alice:x:1001:1001:Alice:/home/alice:/bin/sh\n",
		"group":  "primary:x:1001:\nextra:x:1002:alice\n",
		"shadow": shadow,
	} {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(value), 0600))
	}
	repository := &EtcColonRepository{
		PasswdFilename:          filepath.Join(root, "passwd"),
		GroupFilename:           filepath.Join(root, "group"),
		ShadowFilename:          filepath.Join(root, "shadow"),
		FileSystemSyncThreshold: time.Hour,
	}
	require.NoError(t, repository.Init(t.Context()))
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	return repository, shadow
}

func TestPasswordAccountPolicyReadsFreshStateWithoutPublishingOrPassword(t *testing.T) {
	repository, shadow := newPasswordPolicyFixture(t)
	current, err := CheckPasswordAccount(t.Context(), repository, "alice", 1001, PasswordAccountPolicy{})
	require.NoError(t, err)
	require.Equal(t, "primary", current.Group.Name)
	require.Equal(t, Groups{{1002, "extra"}}, current.Groups)
	// The watcher intentionally cannot publish during this test's check. Fresh
	// group data must still be returned without changing the ordinary cache.
	require.NoError(t, os.WriteFile(repository.GroupFilename, []byte("new-primary:x:1001:\nnew-extra:x:1003:alice\n"), 0600))
	current, err = CheckPasswordAccount(t.Context(), repository, "alice", 1001, PasswordAccountPolicy{})
	require.NoError(t, err)
	require.Equal(t, "new-primary", current.Group.Name)
	require.Equal(t, Groups{{1003, "new-extra"}}, current.Groups)
	cached, err := repository.LookupByName(t.Context(), "alice")
	require.NoError(t, err)
	require.Equal(t, "primary", cached.Group.Name)
	locked := strings.Replace(shadow, "alice:$6$", "alice:!$6$", 1)
	require.NoError(t, os.WriteFile(repository.ShadowFilename, []byte(locked), 0600))
	current, err = CheckPasswordAccount(t.Context(), repository, "alice", 1001, PasswordAccountPolicy{})
	require.Nil(t, current)
	require.ErrorIs(t, err, ErrPasswordAccountPolicyDenied)
	before, err := os.ReadFile(repository.ShadowFilename)
	require.NoError(t, err)
	require.Equal(t, locked, string(before), "eligibility must not rewrite account state")
}

func TestPasswordAccountPolicyRejectsReplacementAmbiguityAndMalformedTarget(t *testing.T) {
	for _, name := range []string{"different UID", "duplicate name", "duplicate UID", "duplicate shadow", "malformed shadow", "missing shadow", "missing user"} {
		t.Run(name, func(t *testing.T) {
			repository, shadow := newPasswordPolicyFixture(t)
			passwd, err := os.ReadFile(repository.PasswdFilename)
			require.NoError(t, err)
			switch name {
			case "different UID":
				passwd = []byte(strings.ReplaceAll(string(passwd), ":1001:1001:", ":2002:1001:"))
			case "duplicate name":
				passwd = append(passwd, passwd...)
			case "duplicate UID":
				passwd = append(passwd, []byte("other:x:1001:1001:Other:/home/other:/bin/sh\n")...)
			case "duplicate shadow":
				shadow += shadow
			case "malformed shadow":
				shadow += "alice:malformed\n"
			case "missing shadow":
				shadow = ""
			case "missing user":
				passwd = nil
			}
			require.NoError(t, os.WriteFile(repository.PasswdFilename, passwd, 0600))
			require.NoError(t, os.WriteFile(repository.ShadowFilename, []byte(shadow), 0600))
			current, err := CheckPasswordAccount(t.Context(), repository, "alice", 1001, PasswordAccountPolicy{})
			require.Nil(t, current)
			require.ErrorIs(t, err, ErrPasswordAccountPolicyDenied)
		})
	}
}

func TestPasswordAccountPolicyDoesNotTreatMalformedMembershipAsAnAbsentGroup(t *testing.T) {
	repository, _ := newPasswordPolicyFixture(t)
	require.NoError(t, os.WriteFile(repository.GroupFilename, []byte("primary:x:1001:\nextra:x:not-a-gid:alice\n"), 0600))
	current, err := CheckPasswordAccount(t.Context(), repository, "alice", 1001, PasswordAccountPolicy{})
	require.Nil(t, current)
	require.ErrorIs(t, err, ErrPasswordAccountPolicyUnavailable)
}

func TestPasswordAccountPolicyDoesNotCreateMissingFilesOrWaitForLocks(t *testing.T) {
	for _, name := range []string{"missing", "locked", "oversized", "too many rows", "special file"} {
		t.Run(name, func(t *testing.T) {
			repository, _ := newPasswordPolicyFixture(t)
			switch name {
			case "missing":
				create := true
				repository.CreateFilesIfAbsent = &create
				require.NoError(t, os.Remove(repository.ShadowFilename))
			case "too many rows":
				require.NoError(t, os.WriteFile(repository.ShadowFilename, []byte(strings.Repeat("\n", maximumPasswordPolicyEntries+1)), 0600))
			case "special file":
				require.NoError(t, os.Remove(repository.ShadowFilename))
				require.NoError(t, syscall.Mkfifo(repository.ShadowFilename, 0600))
			default:
				file, err := os.OpenFile(repository.ShadowFilename, os.O_RDWR, 0600)
				require.NoError(t, err)
				defer file.Close()
				if name == "locked" {
					require.NoError(t, syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))
				} else {
					require.NoError(t, file.Truncate(maximumPasswordPolicyFile+1))
				}
			}
			current, err := CheckPasswordAccount(t.Context(), repository, "alice", 1001, PasswordAccountPolicy{})
			require.Nil(t, current)
			require.ErrorIs(t, err, ErrPasswordAccountPolicyUnavailable)
			if name == "missing" {
				_, err = os.Stat(repository.ShadowFilename)
				require.ErrorIs(t, err, os.ErrNotExist)
			}
		})
	}
}

func TestPasswordPolicyOpenFileRejectsReplacementAndMetadataChange(t *testing.T) {
	for _, name := range []string{"replacement", "mode"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy")
			require.NoError(t, os.WriteFile(path, []byte("original"), 0600))
			file, err := openPasswordPolicyFile(path)
			require.NoError(t, err)
			defer file.Close()
			if name == "replacement" {
				require.NoError(t, os.Rename(path, path+"-old"))
				require.NoError(t, os.WriteFile(path, []byte("replaced"), 0600))
			} else {
				require.NoError(t, os.Chmod(path, 0644))
			}
			require.ErrorIs(t, file.validate(), ErrPasswordAccountPolicyUnavailable)
		})
	}
}

func TestPasswordPolicyShadowDatesLocksAndEmptyPolicy(t *testing.T) {
	const today = 20000
	now := time.Unix(today*24*60*60, 0)
	for _, test := range []struct {
		name   string
		change func(*etcShadowEntry)
	}{
		{"locked", func(v *etcShadowEntry) { v.password = []byte("!hash") }},
		{"disabled", func(v *etcShadowEntry) { v.password = []byte("*hash") }},
		{"missing password", func(v *etcShadowEntry) { v.password = nil }},
		{"password must change", func(v *etcShadowEntry) { v.lastChangedAtInDays = 0 }},
		{"future change", func(v *etcShadowEntry) { v.lastChangedAtInDays = today + 1 }},
		{"password expired", func(v *etcShadowEntry) { v.maximumAgeInDays = 10 }},
		{"account expired", func(v *etcShadowEntry) { v.hasExpire, v.expireAtTsInDays = true, today }},
	} {
		t.Run(test.name, func(t *testing.T) {
			shadow := &etcShadowEntry{password: []byte("hash"), lastChangedAtInDays: today - 10, maximumAgeInDays: 100}
			ref := &etcPasswdRef{&etcPasswdEntry{password: []byte("x")}, shadow}
			require.True(t, passwordPolicyRefEligible(ref, PasswordAccountPolicy{}, now))
			test.change(shadow)
			require.False(t, passwordPolicyRefEligible(ref, PasswordAccountPolicy{}, now))
		})
	}
	ref := &etcPasswdRef{etcPasswdEntry: &etcPasswdEntry{}}
	require.False(t, passwordPolicyRefEligible(ref, PasswordAccountPolicy{}, now))
	require.True(t, passwordPolicyRefEligible(ref, PasswordAccountPolicy{AllowEmpty: true}, now))
	for _, locked := range []string{"x", "!", "*"} {
		ref.etcPasswdEntry.password = []byte(locked)
		require.False(t, passwordPolicyRefEligible(ref, PasswordAccountPolicy{AllowEmpty: true}, now))
	}
	ref.etcShadowEntry = &etcShadowEntry{password: []byte("hash"), lastChangedAtInDays: 1, maximumAgeInDays: ^uint32(0), hasInactiveAge: true, inactiveAgeInDays: ^uint32(0)}
	require.True(t, passwordPolicyRefEligible(ref, PasswordAccountPolicy{}, now), "expiry arithmetic must not wrap uint32")
}

type passwordPolicyTestRepository struct {
	CloseableRepository
	current *User
}

func (*passwordPolicyTestRepository) Init(context.Context) error { return nil }
func (*passwordPolicyTestRepository) Close() error               { return nil }
func (this *passwordPolicyTestRepository) CheckPasswordAccount(context.Context, string, Id, PasswordAccountPolicy) (*User, error) {
	return this.current, nil
}

func TestPasswordAccountPolicySharedCapabilityAndIdentityChecks(t *testing.T) {
	raw := &passwordPolicyTestRepository{current: &User{Name: "alice", Uid: 1001}}
	provider := &SharedRepositoryProvider[*passwordPolicyTestRepository]{V: raw}
	shared, err := provider.Create(t.Context())
	require.NoError(t, err)
	defer shared.Close()
	current, err := CheckPasswordAccount(t.Context(), shared, "alice", 1001, PasswordAccountPolicy{})
	require.NoError(t, err)
	require.Equal(t, raw.current, current)
	raw.current = &User{Name: "alice", Uid: 2002}
	current, err = CheckPasswordAccount(t.Context(), shared, "alice", 1001, PasswordAccountPolicy{})
	require.Nil(t, current)
	require.ErrorIs(t, err, ErrPasswordAccountPolicyDenied)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	current, err = CheckPasswordAccount(ctx, shared, "alice", 1001, PasswordAccountPolicy{})
	require.Nil(t, current)
	require.ErrorIs(t, err, context.Canceled)
	current, err = CheckPasswordAccount(t.Context(), nil, "alice", 1001, PasswordAccountPolicy{})
	require.Nil(t, current)
	require.ErrorIs(t, err, ErrPasswordAccountPolicyUnavailable)
}
