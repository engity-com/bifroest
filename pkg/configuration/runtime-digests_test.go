package configuration

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuntimeDigestsCompareEffectiveReferencesAndIgnoreUnusedDefinitions(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	original := snapshotTestLoad(t, snapshotTestSource)
	want, err := original.RuntimeDigests(key)
	require.NoError(t, err)
	source := strings.Replace(snapshotTestSource, "unused-environment", "changed-unused-environment", 1)
	source = strings.ReplaceAll(source, "environment: shared", "environment: {type: dummy, banner: original-environment}")
	source = strings.ReplaceAll(source, "authorization: shared", `authorization: {type: simple, entries: [{name: alice, password: "plain:original-password"}]}`)
	equivalent := snapshotTestLoad(t, "# formatting is not runtime state\n"+source)
	got, err := equivalent.RuntimeDigests(key)
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.True(t, original.configuration.Flows[0].Environment.Reference != "", "digest calculation must not rewrite the snapshot")
	changedKey, err := original.RuntimeDigests(bytes.Repeat([]byte{8}, 32))
	require.NoError(t, err)
	require.NotEqual(t, want["first"], changedKey["first"])
}

func TestRuntimeDigestsIncludeSharedEnvironmentAndAuthorizationValues(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	first := snapshotTestLoad(t, snapshotTestSource)
	initial, err := first.RuntimeDigests(key)
	require.NoError(t, err)
	environment := snapshotTestLoad(t, strings.Replace(snapshotTestSource, "banner: original-environment", "banner: original-environment, exitCode: 17", 1))
	changed, err := environment.RuntimeDigests(key)
	require.NoError(t, err)
	for _, name := range []FlowName{"first", "second"} {
		require.NotEqual(t, initial[name].Environment, changed[name].Environment)
		require.NotEqual(t, initial[name].Owner, changed[name].Owner)
	}
	require.Equal(t, initial["independent"], changed["independent"])
	authorization := snapshotTestLoad(t, strings.Replace(snapshotTestSource, "original-password", "changed-password", 1))
	changed, err = authorization.RuntimeDigests(key)
	require.NoError(t, err)
	require.Equal(t, initial["first"].Environment, changed["first"].Environment)
	require.NotEqual(t, initial["first"].Owner, changed["first"].Owner)
	require.NotContains(t, changed["first"].Owner, "changed-password")
}

func TestRuntimeDigestsRequirePrivateKeyAndDoNotExposeConfiguration(t *testing.T) {
	snapshot := snapshotTestLoad(t, snapshotTestSource)
	for _, key := range [][]byte{nil, {1}, make([]byte, 31), make([]byte, 33)} {
		digests, err := snapshot.RuntimeDigests(key)
		require.Error(t, err)
		require.Nil(t, digests)
		require.NotContains(t, err.Error(), "original-password")
	}
}

func TestRuntimeDigestsIncludeOnlyTheReferencedAuditlog(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	source := "auditlogs:\n  shared: {minimumFreeBytes: 1, directory: shared-audit, identityFile: shared-key}\n  unused: {minimumFreeBytes: 1, directory: unused-audit, identityFile: unused-key}\n" +
		strings.Replace(snapshotTestSource, "name: first,", "name: first, auditlog: shared,", 1)
	before, err := snapshotTestLoad(t, source).RuntimeDigests(key)
	require.NoError(t, err)
	changed, err := snapshotTestLoad(t, strings.Replace(source, "shared: {minimumFreeBytes: 1,", "shared: {minimumFreeBytes: 2,", 1)).RuntimeDigests(key)
	require.NoError(t, err)
	require.Equal(t, before["first"].Environment, changed["first"].Environment)
	require.NotEqual(t, before["first"].Owner, changed["first"].Owner)
	require.Equal(t, before["independent"], changed["independent"])
	unused, err := snapshotTestLoad(t, strings.Replace(source, "unused: {minimumFreeBytes: 1,", "unused: {minimumFreeBytes: 2,", 1)).RuntimeDigests(key)
	require.NoError(t, err)
	require.Equal(t, before, unused)
}
