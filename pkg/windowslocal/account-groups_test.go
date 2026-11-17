package windowslocal

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSAMGroupsAreFreshCopiedAndOrderIndependent(t *testing.T) {
	source := []group{{"second", "S-1-5-21-22"}, {"first", "S-1-5-21-11"}}
	reads, checks := 0, 0
	identity := func() error { checks++; return nil }
	read := func() ([]group, error) { reads++; return source, nil }
	before, err := inspectSAMGroupsFlow(t.Context(), identity, read)
	require.NoError(t, err)
	require.Equal(t, 2, checks)
	require.Equal(t, 1, reads)
	require.Equal(t, []group{{"first", "S-1-5-21-11"}, {"second", "S-1-5-21-22"}}, before)
	source[0], source[1] = source[1], source[0]
	reordered, err := inspectSAMGroupsFlow(t.Context(), identity, read)
	require.NoError(t, err)
	require.True(t, sameSAMGroups(before, reordered))
	source[0].Name = "renamed"
	renamed, err := inspectSAMGroupsFlow(t.Context(), identity, read)
	require.NoError(t, err)
	require.False(t, sameSAMGroups(before, renamed))
	require.Equal(t, "first", before[0].Name, "prior request-local observation must not alias the native reader's next slice")
	source = append(source, group{"added", "S-1-5-21-33"})
	added, err := inspectSAMGroupsFlow(t.Context(), identity, read)
	require.NoError(t, err)
	require.False(t, sameSAMGroups(renamed, added))
	require.Equal(t, 4, reads)
}

func TestSAMGroupsRejectIncompleteAmbiguousOrFailedObservations(t *testing.T) {
	for _, scenario := range []string{"identity-before", "identity-after", "read-error", "cancel-before", "cancel-read", "cancel-after", "empty-name", "empty-sid", "duplicate-name", "duplicate-sid"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			failure := errors.New("native group identity error")
			checks, reads := 0, 0
			result, err := inspectSAMGroupsFlow(ctx, func() error {
				checks++
				if scenario == "identity-before" && checks == 1 || scenario == "identity-after" && checks == 2 {
					return failure
				}
				if scenario == "cancel-before" && checks == 1 || scenario == "cancel-after" && checks == 2 {
					cancel()
				}
				return nil
			}, func() ([]group, error) {
				reads++
				if scenario == "read-error" {
					return []group{{"partial", "partial"}}, failure
				}
				if scenario == "cancel-read" {
					cancel()
				}
				groups := []group{{"member", "S-1-5-21-11"}}
				switch scenario {
				case "empty-name":
					groups[0].Name = ""
				case "empty-sid":
					groups[0].SID = ""
				case "duplicate-name":
					groups = append(groups, group{"MEMBER", "S-1-5-21-22"})
				case "duplicate-sid":
					groups = append(groups, group{"other", "S-1-5-21-11"})
				}
				return groups, nil
			})
			require.Nil(t, result)
			require.Error(t, err)
			if scenario == "identity-before" || scenario == "cancel-before" {
				require.Zero(t, reads)
			} else {
				require.Equal(t, 1, reads)
			}
			if scenario == "identity-after" || scenario == "cancel-after" {
				require.Equal(t, 2, checks)
			} else {
				require.Equal(t, 1, checks)
			}
		})
	}
}

func TestSAMGroupsRequireLiveContextAndOperationsButAllowNoMemberships(t *testing.T) {
	called := false
	identity := func() error { called = true; return nil }
	read := func() ([]group, error) { called = true; return nil, nil }
	_, err := inspectSAMGroupsFlow(nil, identity, read)
	require.Error(t, err)
	_, err = inspectSAMGroupsFlow(t.Context(), nil, read)
	require.Error(t, err)
	_, err = inspectSAMGroupsFlow(t.Context(), identity, nil)
	require.Error(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = inspectSAMGroupsFlow(ctx, identity, read)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, called)
	groups, err := inspectSAMGroupsFlow(t.Context(), identity, read)
	require.NoError(t, err)
	require.Empty(t, groups)
}
