package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	berrors "github.com/engity-com/bifroest/pkg/errors"
)

type identityResolutionTestLookup struct {
	byName func(context.Context, string) (string, string, error)
	bySID  func(context.Context, string) (string, string, error)
}

func (this identityResolutionTestLookup) LookupIdentityByName(ctx context.Context, name string) (string, string, error) {
	return this.byName(ctx, name)
}
func (this identityResolutionTestLookup) LookupIdentityBySID(ctx context.Context, sid string) (string, string, error) {
	return this.bySID(ctx, sid)
}

func TestResolveIdentityUsesOneSelectorAndEnforcesSuppliedSID(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	for _, test := range []struct {
		label, name, sid string
		mismatch         bool
	}{
		{"name", "ALICE", "", false},
		{"SID", "", sid, false},
		{"matching name and SID", "ALICE", sid, false},
		{"mismatching name and SID", "ALICE", "S-1-5-21-1-2-3-1002", true},
		{"mismatching SID response", "", "S-1-5-21-1-2-3-1002", true},
	} {
		t.Run(test.label, func(t *testing.T) {
			nameCalls, sidCalls := 0, 0
			lookup := identityResolutionTestLookup{
				byName: func(ctx context.Context, name string) (string, string, error) {
					nameCalls++
					require.Same(t, t.Context(), ctx)
					require.Equal(t, test.name, name)
					return "canonical", sid, nil // Preserve the native provider's canonical name.
				},
				bySID: func(_ context.Context, value string) (string, string, error) {
					sidCalls++
					require.Equal(t, test.sid, value)
					return "canonical", sid, nil
				},
			}
			name, resolvedSID, err := ResolveIdentity(t.Context(), lookup, test.name, test.sid)
			if test.mismatch {
				require.ErrorIs(t, err, ErrInvalidAccountFacts)
				require.ErrorContains(t, err, "does not match UID")
				require.True(t, berrors.Config.IsErr(err))
				require.Empty(t, name)
				require.Empty(t, resolvedSID)
			} else {
				require.NoError(t, err)
				require.Equal(t, "canonical", name)
				require.Equal(t, sid, resolvedSID)
			}
			require.Equal(t, 1, nameCalls+sidCalls)
			require.Equal(t, test.name != "", nameCalls == 1)
		})
	}
}

func TestResolveIdentityUsesOnlyModeledAccountFacts(t *testing.T) {
	facts := accountSnapshotTestFacts()
	account, err := NewAccountSnapshot(facts)
	require.NoError(t, err)
	lookup, err := NewMemoryLookup(AccountLookupFacts{Accounts: []*AccountSnapshot{account}, AbsentNames: []string{"absent"}, AbsentSIDs: []string{"S-1-5-18"}})
	require.NoError(t, err)
	for _, test := range []struct {
		name, sid string
		err       error
	}{
		{"ALICE", "", nil}, {"", facts.Identity.SID, nil}, {"Alice", facts.Identity.SID, nil},
		{"absent", "", ErrNotFound}, {"", "S-1-5-18", ErrNotFound},
		{"Administrator", "", ErrAccountNotModeled}, {"", "S-1-5-19", ErrAccountNotModeled},
		// A known SID must not substitute for an unknown or explicitly absent name.
		{"absent", facts.Identity.SID, ErrNotFound}, {"unmodeled", facts.Identity.SID, ErrAccountNotModeled},
	} {
		t.Run(test.name+test.sid, func(t *testing.T) {
			name, sid, err := ResolveIdentity(t.Context(), lookup, test.name, test.sid)
			if test.err != nil {
				require.ErrorIs(t, err, test.err)
				require.Empty(t, name)
				require.Empty(t, sid)
				return
			}
			require.NoError(t, err)
			require.Equal(t, facts.Identity.Name, name)
			require.Equal(t, facts.Identity.SID, sid)
		})
	}
}

func TestResolveIdentityRejectsUnavailableSourcesAndInvalidResults(t *testing.T) {
	for _, lookup := range []IdentityLookup{nil, (*MemoryLookup)(nil), &MemoryLookup{}, (*identityResolutionTestLookup)(nil)} {
		_, _, err := ResolveIdentity(t.Context(), lookup, "alice", "")
		require.ErrorIs(t, err, ErrAccountLookupUnavailable)
		require.True(t, berrors.System.IsErr(err))
	}
	_, _, err := ResolveIdentity(nil, identityResolutionTestLookup{}, "alice", "")
	require.ErrorIs(t, err, ErrAccountLookupUnavailable)
	for _, name := range []string{"", `DOMAIN\alice`, "alice@domain", " alice", "alice."} {
		_, _, err := ResolveIdentity(t.Context(), identityResolutionTestLookup{}, name, "")
		require.ErrorIs(t, err, ErrInvalidAccountFacts)
	}
	for _, test := range []struct{ name, sid string }{
		{"", "S-1-5-18"}, {"alice", ""}, {`DOMAIN\alice`, "S-1-5-18"}, {"alice", "invalid\nSID"},
	} {
		lookup := identityResolutionTestLookup{byName: func(context.Context, string) (string, string, error) { return test.name, test.sid, nil }}
		name, sid, err := ResolveIdentity(t.Context(), lookup, "alice", "")
		require.ErrorIs(t, err, ErrInvalidAccountFacts)
		require.Empty(t, name)
		require.Empty(t, sid)
	}
}

func TestResolveIdentityPreservesFailuresAndCancellation(t *testing.T) {
	for _, upstream := range []error{
		ErrNotFound, ErrAccountNotModeled, ErrAccountLookupUnavailable, ErrInvalidAccountFacts,
		context.Canceled, context.DeadlineExceeded, errors.New("untyped source failure"),
		berrors.Unknown.Newf("unknown source failure"), berrors.User.Newf("user failure"),
		berrors.Config.Newf("fixture failure"), berrors.System.Newf("system failure"), berrors.Network.Newf("network failure"),
		berrors.Permission.Newf("permission failure"), berrors.Expired.Newf("expired failure"),
		errors.Join(ErrNotFound, ErrAccountNotModeled),
	} {
		lookup := identityResolutionTestLookup{byName: func(context.Context, string) (string, string, error) {
			return "untrusted", "untrusted", fmt.Errorf("wrapped: %w", upstream)
		}}
		name, sid, err := ResolveIdentity(t.Context(), lookup, "alice", "")
		require.ErrorIs(t, err, upstream)
		require.Empty(t, name)
		require.Empty(t, sid)
		if typed, ok := berrors.IsError(upstream); ok {
			require.True(t, typed.Type.IsErr(err))
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	lookup := identityResolutionTestLookup{byName: func(context.Context, string) (string, string, error) {
		calls++
		cancel()
		return "", "", ErrNotFound
	}}
	_, _, err := ResolveIdentity(ctx, lookup, "alice", "")
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, berrors.System.IsErr(err))
	_, _, err = ResolveIdentity(ctx, lookup, "alice", "")
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, calls)
	expired, cancelDeadline := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	_, _, err = ResolveIdentity(expired, identityResolutionTestLookup{}, "alice", "")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.True(t, berrors.System.IsErr(err))
}

func TestResolveIdentityKeepsParallelEvaluationsIndependent(t *testing.T) {
	facts := accountSnapshotTestFacts()
	account, err := NewAccountSnapshot(facts)
	require.NoError(t, err)
	lookup, err := NewMemoryLookup(AccountLookupFacts{Accounts: []*AccountSnapshot{account}})
	require.NoError(t, err)
	for range 16 {
		t.Run("reader", func(t *testing.T) {
			t.Parallel()
			for range 5 {
				name, sid, err := ResolveIdentity(t.Context(), lookup, "ALICE", facts.Identity.SID)
				require.NoError(t, err)
				require.Equal(t, "alice", name)
				require.Equal(t, facts.Identity.SID, sid)
			}
		})
	}
}

func TestValidSAMNamePreservesLexicalRulesWithoutResolvingAccounts(t *testing.T) {
	for _, value := range []string{"alice", "ALICE", "some user", "Müller", "名字", "a$", "😀", strings.Repeat("x", 100)} {
		require.True(t, ValidSAMName(value), "%q", value)
	}
	for _, value := range []string{"", ".", "..", ".\\alice", `host\alice`, "alice@host", " alice", "alice ", "alice.", "invalid\nname", "invalid\x00name", "\xff"} {
		require.False(t, ValidSAMName(value), "%q", value)
	}
	for _, value := range `\/@"[]:;|=,+*?<>` {
		require.False(t, ValidSAMName("account"+string(value)+"name"))
	}
}
