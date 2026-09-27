//go:build unix

package environment

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/user"
)

const (
	credentialHelperMarker = "BIFROEST_CREDENTIAL_HELPER"
	credentialHelperUID    = "BIFROEST_CREDENTIAL_UID"
	credentialHelperGID    = "BIFROEST_CREDENTIAL_GID"
	credentialHelperGroups = "BIFROEST_CREDENTIAL_GROUPS"
)

func TestLocalCredentialImpersonationChild(t *testing.T) {
	if os.Getenv(credentialHelperMarker) == "1" {
		assertCredentialHelperIdentity(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("credential impersonation requires effective UID 0")
	}

	target, err := existingCredentialTestUser()
	if err != nil {
		t.Skipf("no safe existing non-root target identity is available: %v", err)
	}
	credentials, err := credentialsForUser(target, os.Geteuid())
	require.NoError(t, err)

	executable := copyCredentialHelperExecutable(t)
	cmd := exec.Command(executable, "-test.run=^TestLocalCredentialImpersonationChild$")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credentials}
	cmd.Env = append(os.Environ(),
		credentialHelperMarker+"=1",
		credentialHelperUID+"="+strconv.FormatUint(uint64(credentials.Uid), 10),
		credentialHelperGID+"="+strconv.FormatUint(uint64(credentials.Gid), 10),
		credentialHelperGroups+"="+formatCredentialGroups(credentials.Groups),
	)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "credential helper failed: %s", output)
}

func assertCredentialHelperIdentity(t *testing.T) {
	wantUID, err := strconv.ParseUint(os.Getenv(credentialHelperUID), 10, 32)
	require.NoError(t, err)
	wantGID, err := strconv.ParseUint(os.Getenv(credentialHelperGID), 10, 32)
	require.NoError(t, err)
	wantGroups, err := parseCredentialGroups(os.Getenv(credentialHelperGroups))
	require.NoError(t, err)

	actualGroups, err := os.Getgroups()
	require.NoError(t, err)
	gotGroups := make([]uint32, 0, len(actualGroups))
	for _, group := range actualGroups {
		if uint32(group) != uint32(os.Getegid()) {
			gotGroups = append(gotGroups, uint32(group))
		}
	}
	slices.Sort(gotGroups)
	slices.Sort(wantGroups)

	require.Equal(t, uint32(wantUID), uint32(os.Geteuid()))
	require.Equal(t, uint32(wantGID), uint32(os.Getegid()))
	require.Equal(t, wantGroups, gotGroups)
}

func existingCredentialTestUser() (*user.User, error) {
	var failures []string
	for _, name := range []string{"daemon", "nobody", "_daemon", "_nobody"} {
		native, err := osuser.Lookup(name)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		uid, err := parseNativeCredentialID(native.Uid)
		if err != nil || uid == 0 {
			failures = append(failures, fmt.Sprintf("%s: invalid non-root UID %q", name, native.Uid))
			continue
		}
		gid, err := parseNativeCredentialID(native.Gid)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: invalid primary GID %q", name, native.Gid))
			continue
		}
		nativeGroupIDs, err := native.GroupIds()
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: cannot resolve groups: %v", name, err))
			continue
		}

		groups := make(user.Groups, 0, len(nativeGroupIDs))
		seen := make(map[uint32]struct{}, len(nativeGroupIDs))
		for _, nativeGroupID := range nativeGroupIDs {
			groupID, err := parseNativeCredentialID(nativeGroupID)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: invalid supplementary GID %q", name, nativeGroupID))
				groups = nil
				break
			}
			if groupID == gid {
				continue
			}
			if _, exists := seen[groupID]; exists {
				continue
			}
			seen[groupID] = struct{}{}
			groups = append(groups, user.Group{Gid: user.GroupId(groupID)})
		}
		if groups == nil {
			continue
		}

		return &user.User{
			Name:   native.Username,
			Uid:    user.Id(uid),
			Group:  user.Group{Gid: user.GroupId(gid)},
			Groups: groups,
		}, nil
	}
	return nil, fmt.Errorf("%s", strings.Join(failures, "; "))
}

func parseNativeCredentialID(value string) (uint32, error) {
	if unsigned, err := strconv.ParseUint(value, 10, 32); err == nil {
		return uint32(unsigned), nil
	}
	signed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(int32(signed)), nil
}

func copyCredentialHelperExecutable(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "bifroest-credential-test-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(directory)) })
	require.NoError(t, os.Chmod(directory, 0o755))

	source, err := os.Open(os.Args[0])
	require.NoError(t, err)
	defer source.Close()
	targetName := filepath.Join(directory, "credential-helper")
	target, err := os.OpenFile(targetName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	require.NoError(t, err)
	_, copyErr := io.Copy(target, source)
	closeErr := target.Close()
	require.NoError(t, copyErr)
	require.NoError(t, closeErr)
	return targetName
}

func formatCredentialGroups(groups []uint32) string {
	values := make([]string, len(groups))
	for i, group := range groups {
		values[i] = strconv.FormatUint(uint64(group), 10)
	}
	return strings.Join(values, ",")
}

func parseCredentialGroups(value string) ([]uint32, error) {
	groups := make([]uint32, 0)
	if value == "" {
		return groups, nil
	}
	for _, part := range strings.Split(value, ",") {
		group, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, err
		}
		groups = append(groups, uint32(group))
	}
	return groups, nil
}
