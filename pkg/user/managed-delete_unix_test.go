//go:build unix

package user

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
)

func TestDeleteByIdentityDoesNotRequireManagementGroup(t *testing.T) {
	dir := newTestDir(t)
	repository := &EtcColonRepository{
		PasswdFilename: dir.file("passwd").setContent("alice:x:1001:1001::/home/alice:/bin/sh\n").name(),
		GroupFilename:  dir.file("group").setContent("ordinary:x:1001:alice\n").name(),
		ShadowFilename: dir.file("shadow").setContent("alice:!:19722:0:99999:7:::\n").name(),
	}
	ctx := context.Background()
	require.NoError(t, repository.Init(ctx))
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	opts := &DeleteOpts{HomeDir: common.P(false), KillProcesses: common.P(false)}
	require.Error(t, repository.DeleteByIdentity(ctx, 1001, "bob", "/home/alice", opts))
	require.ErrorContains(t, repository.DeleteByIdentity(ctx, 1001, "alice", "/tmp/changed-home", &DeleteOpts{
		HomeDir: common.P(true), KillProcesses: common.P(false),
	}), "changed home directory")
	_, err := repository.LookupByName(ctx, "alice")
	require.NoError(t, err)
	require.NoError(t, repository.DeleteByIdentity(ctx, 1001, "alice", "/home/alice", opts))
	_, err = repository.LookupByName(ctx, "alice")
	require.ErrorIs(t, err, ErrNoSuchUser)
}

func TestEnsureIndexesCreatedAndRenamedUsersByIdentity(t *testing.T) {
	dir := newTestDir(t)
	repository := &EtcColonRepository{
		PasswdFilename: dir.file("passwd").setContent("other:x:1000:1000::/home/other:/bin/sh\n").name(),
		GroupFilename:  dir.file("group").setContent("existing:x:1000:\n").name(),
		ShadowFilename: dir.file("shadow").setContent("other:!:19722:0:99999:7:::\n").name(),
	}
	ctx := context.Background()
	require.NoError(t, repository.Init(ctx))
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	uid := Id(2001)
	requirement := &Requirement{
		Name: "alice", Uid: &uid, Group: GroupRequirement{Name: "existing"},
		Groups: GroupRequirements{{Name: "existing"}}, Shell: "/bin/sh", HomeDir: dir.child("home"),
	}
	opts := &EnsureOpts{HomeDir: common.P(false)}
	created, result, err := repository.Ensure(ctx, requirement, opts)
	require.NoError(t, err)
	require.Equal(t, EnsureResultCreated, result)
	require.Equal(t, uid, created.Uid)
	byUID, err := repository.LookupById(ctx, uid)
	require.NoError(t, err)
	require.Equal(t, "alice", byUID.Name)
	other, err := repository.LookupById(ctx, 1000)
	require.NoError(t, err)
	require.Equal(t, "other", other.Name)

	requirement.Name = "renamed"
	renamed, result, err := repository.Ensure(ctx, requirement, opts)
	require.NoError(t, err)
	require.Equal(t, EnsureResultModified, result)
	require.Equal(t, "renamed", renamed.Name)
	_, err = repository.LookupByName(ctx, "alice")
	require.ErrorIs(t, err, ErrNoSuchUser)
	current, err := repository.LookupByName(ctx, "renamed")
	require.NoError(t, err)
	require.Equal(t, uid, current.Uid)
}

func TestDeleteByIdentityRejectsUnsafeOrSharedHomes(t *testing.T) {
	for _, test := range []struct {
		name      string
		home      func(*testDir) string
		otherUser bool
		want      string
	}{
		{name: "filesystem root", home: func(*testDir) string { return "/" }, want: "unsafe home"},
		{name: "shared", home: func(dir *testDir) string { return dir.child("shared") }, otherUser: true, want: "shared home"},
		{name: "wrong owner", home: func(dir *testDir) string { return dir.child("owned-by-test") }, want: "not exclusively owned"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := newTestDir(t)
			home := test.home(dir)
			uid := uint32(1001)
			if int(uid) == os.Getuid() {
				uid = 1003
			}
			if test.name == "wrong owner" {
				require.NoError(t, os.Mkdir(home, 0700))
			}
			passwd := fmt.Sprintf("alice:x:%d:1001::%s:/bin/sh\n", uid, home)
			shadow := "alice:!:19722:0:99999:7:::\n"
			if test.otherUser {
				passwd += "bob:x:1002:1001::" + home + ":/bin/sh\n"
				shadow += "bob:!:19722:0:99999:7:::\n"
			}
			repository := &EtcColonRepository{
				PasswdFilename: dir.file("passwd").setContent(passwd).name(),
				GroupFilename:  dir.file("group").setContent("ordinary:x:1001:alice,bob\n").name(),
				ShadowFilename: dir.file("shadow").setContent(shadow).name(),
			}
			ctx := context.Background()
			require.NoError(t, repository.Init(ctx))
			t.Cleanup(func() { require.NoError(t, repository.Close()) })
			err := repository.DeleteByIdentity(ctx, Id(uid), "alice", home, &DeleteOpts{
				HomeDir: common.P(true), KillProcesses: common.P(false),
			})
			require.ErrorContains(t, err, test.want)
			_, err = repository.LookupByName(ctx, "alice")
			require.NoError(t, err)
		})
	}
}
