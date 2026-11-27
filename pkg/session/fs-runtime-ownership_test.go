package session

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestFsRuntimeOwnershipAndPrivateKeySurviveRestart(t *testing.T) {
	repo, conf := newAssociationRepository(t)
	state := runtimeOwnershipTestState(t)
	key, err := repo.RuntimeKey(t.Context())
	require.NoError(t, err)
	require.Len(t, key, 32)
	require.NoError(t, repo.CommitRuntimeState(t.Context(), "", *state).Err)
	ctx := WithRuntimeOwnership(t.Context(), state.Flows["work"])
	sess, err := repo.Create(ctx, "work", associationRemote("alice"), []byte("secret-credential"))
	require.NoError(t, err)
	owner, err := sess.(RuntimeOwnershipSession).RuntimeOwnership(t.Context())
	require.NoError(t, err)
	require.True(t, owner.Matches(state.Flows["work"]))
	require.Equal(t, sess.Id(), owner.SessionID)
	path, err := repo.file("work", sess.Id(), FsFileRuntimeOwnership)
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "secret-credential")
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
	require.NoError(t, repo.Close())
	reopened, err := NewFsRepository(t.Context(), conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	loaded, err := reopened.RuntimeState(t.Context())
	require.NoError(t, err)
	require.Equal(t, state, loaded)
	keyAgain, err := reopened.RuntimeKey(t.Context())
	require.NoError(t, err)
	require.Equal(t, key, keyAgain)
	loaded.Flows["work"] = RuntimeFlow{}
	keyAgain[0] ^= 255
	loaded, err = reopened.RuntimeState(t.Context())
	require.NoError(t, err)
	require.Equal(t, state, loaded, "callers cannot mutate durable state through a returned map")
	found, err := reopened.FindBy(t.Context(), "work", sess.Id(), nil)
	require.NoError(t, err)
	restored, err := found.(RuntimeOwnershipSession).RuntimeOwnership(t.Context())
	require.NoError(t, err)
	require.Equal(t, owner, restored)
}

func TestFsRuntimeStateCASHasOneWinnerAndRejectsClosedWriters(t *testing.T) {
	repo, _ := newAssociationRepository(t)
	_, err := repo.RuntimeKey(t.Context())
	require.NoError(t, err)
	first := runtimeOwnershipTestState(t)
	require.NoError(t, repo.CommitRuntimeState(t.Context(), "", *first).Err)
	const count = 12
	results := make(chan RuntimeCommit, count)
	var workers sync.WaitGroup
	for range count {
		next, err := AdvanceRuntimeState(first, runtimeOwnershipTestDigests())
		require.NoError(t, err)
		workers.Go(func() { results <- repo.CommitRuntimeState(t.Context(), first.Revision, *next) })
	}
	workers.Wait()
	close(results)
	winners := 0
	for result := range results {
		require.False(t, result.Uncertain)
		if result.Published {
			winners++
			require.NoError(t, result.Err)
		} else {
			require.ErrorIs(t, result.Err, ErrRuntimeStateConflict)
		}
	}
	require.Equal(t, 1, winners)
	loaded, err := repo.RuntimeState(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, first.Revision, loaded.Revision)
	next, err := AdvanceRuntimeState(loaded, runtimeOwnershipTestDigests())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, repo.CommitRuntimeState(ctx, loaded.Revision, *next).Err, context.Canceled)
	require.NoError(t, repo.Close())
	require.Error(t, repo.CommitRuntimeState(t.Context(), loaded.Revision, *next).Err)
	_, err = repo.RuntimeKey(t.Context())
	require.Error(t, err)
}

func TestFsRuntimeStatePublicationErrorsAreNotMistakenForRejection(t *testing.T) {
	for _, mode := range []string{"before", "after", "uncertain", "lost", "damaged"} {
		t.Run(mode, func(t *testing.T) {
			repo, _ := newAssociationRepository(t)
			_, err := repo.RuntimeKey(t.Context())
			require.NoError(t, err)
			first := runtimeOwnershipTestState(t)
			require.NoError(t, repo.CommitRuntimeState(t.Context(), "", *first).Err)
			next, err := AdvanceRuntimeState(first, runtimeOwnershipTestDigests())
			require.NoError(t, err)
			injected := errors.New("injected durable write failure")
			result := repo.commitRuntimeState(t.Context(), first.Revision, *next, func(path string, raw []byte, modeBits os.FileMode) error {
				if mode == "after" {
					runtimeTestReplaceWithoutDirectorySync(t, path, raw)
				}
				if mode == "uncertain" {
					require.NoError(t, os.WriteFile(path, []byte("unreadable result"), 0600))
					require.NoError(t, os.Remove(path))
					require.NoError(t, os.Mkdir(path, 0700))
				}
				if mode == "lost" {
					require.NoError(t, os.Remove(path))
				}
				if mode == "damaged" {
					require.NoError(t, os.WriteFile(path, []byte("secret-damaged-result"), 0600))
				}
				return injected
			})
			require.ErrorIs(t, result.Err, injected)
			require.Equal(t, mode == "after", result.Published)
			require.Equal(t, mode != "before" && mode != "after", result.Uncertain)
			if mode == "before" {
				loaded, err := repo.RuntimeState(t.Context())
				require.NoError(t, err)
				require.Equal(t, first, loaded)
			} else {
				require.FileExists(t, repo.runtimeFile(FsFileRuntimePending))
				_, err := repo.RuntimeState(t.Context())
				require.ErrorIs(t, err, ErrInvalidRuntimeState, "an unfinished durable intent must block implicit restart recovery")
			}
		})
	}
}

// Exercise a real atomic replacement without a successful directory sync, not
// a fully durable write followed by an unrelated injected error.
func runtimeTestReplaceWithoutDirectorySync(t *testing.T, path string, raw []byte) {
	t.Helper()
	file, err := os.CreateTemp(filepath.Dir(path), ".runtime-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(file.Name()) })
	_, err = file.Write(raw)
	require.NoError(t, err)
	require.NoError(t, file.Sync())
	require.NoError(t, file.Close())
	require.NoError(t, replaceFsFile(file.Name(), path))
}

func TestFsRuntimePendingIntentBlocksRestartAndFurtherWrites(t *testing.T) {
	for _, operation := range []string{"state", "revocation"} {
		t.Run(operation, func(t *testing.T) {
			repo, conf := newAssociationRepository(t)
			_, err := repo.RuntimeKey(t.Context())
			require.NoError(t, err)
			state := runtimeOwnershipTestState(t)
			require.NoError(t, repo.CommitRuntimeState(t.Context(), "", *state).Err)
			sess, err := repo.Create(WithRuntimeOwnership(t.Context(), state.Flows["work"]), "work", associationRemote("alice"), nil)
			require.NoError(t, err)
			injected := errors.New("injected post-rename sync failure")
			write := func(path string, raw []byte, _ os.FileMode) error {
				require.FileExists(t, repo.runtimeFile(FsFileRuntimePending))
				runtimeTestReplaceWithoutDirectorySync(t, path, raw)
				return injected
			}
			next := runtimeOwnershipTestState(t)
			if operation == "state" {
				result := repo.commitRuntimeState(t.Context(), state.Revision, *next, write)
				require.True(t, result.Published)
				require.False(t, result.Uncertain)
				require.ErrorIs(t, result.Err, injected)
			} else {
				require.ErrorIs(t, repo.revokeRuntimeSession(t.Context(), sess.Flow(), sess.Id(), write), injected)
			}
			pending, err := os.ReadFile(repo.runtimeFile(FsFileRuntimePending))
			require.NoError(t, err)
			require.NoError(t, repo.Close())
			reopened, err := NewFsRepository(t.Context(), conf)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, reopened.Close()) })
			_, err = reopened.RuntimeState(t.Context())
			require.ErrorIs(t, err, ErrInvalidRuntimeState)
			require.ErrorIs(t, reopened.CommitRuntimeState(t.Context(), state.Revision, *runtimeOwnershipTestState(t)).Err, ErrInvalidRuntimeState)
			require.ErrorIs(t, reopened.RevokeRuntimeSession(t.Context(), sess.Flow(), sess.Id()), ErrInvalidRuntimeState)
			retained, err := os.ReadFile(reopened.runtimeFile(FsFileRuntimePending))
			require.NoError(t, err)
			require.Equal(t, pending, retained)
		})
	}
}

func TestFsRuntimeCopiedRevocationCannotRevokeOrBeOverwrittenForAnotherSession(t *testing.T) {
	repo, _ := newAssociationRepository(t)
	state := runtimeOwnershipTestState(t)
	ctx := WithRuntimeOwnership(t.Context(), state.Flows["work"])
	first, err := repo.Create(ctx, "work", associationRemote("alice"), nil)
	require.NoError(t, err)
	second, err := repo.Create(ctx, "work", associationRemote("alice"), nil)
	require.NoError(t, err)
	require.NoError(t, repo.RevokeRuntimeSession(t.Context(), first.Flow(), first.Id()))
	path, err := repo.file(first.Flow(), first.Id(), FsFileRuntimeRevocation)
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	copied, err := repo.file(second.Flow(), second.Id(), FsFileRuntimeRevocation)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(copied, raw, 0600))
	revoked, err := second.(RuntimeOwnershipSession).RuntimeRevoked(t.Context())
	require.True(t, revoked, "a foreign marker denies access, never grants it")
	require.ErrorIs(t, err, ErrInvalidRuntimeOwnership)
	require.ErrorIs(t, repo.RevokeRuntimeSession(t.Context(), second.Flow(), second.Id()), ErrInvalidRuntimeOwnership)
	retained, err := os.ReadFile(copied)
	require.NoError(t, err)
	require.Equal(t, raw, retained)
}

func TestFsRuntimeRevocationIsDurableAndMalformedTombstoneIsPreserved(t *testing.T) {
	repo, conf := newAssociationRepository(t)
	state := runtimeOwnershipTestState(t)
	sess, err := repo.Create(WithRuntimeOwnership(t.Context(), state.Flows["work"]), "work", associationRemote("alice"), nil)
	require.NoError(t, err)
	require.NoError(t, repo.RevokeRuntimeSession(t.Context(), sess.Flow(), sess.Id()))
	require.NoError(t, repo.Close())
	restarted, err := NewFsRepository(t.Context(), conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.Close()) })
	found, err := restarted.FindBy(t.Context(), sess.Flow(), sess.Id(), nil)
	require.NoError(t, err)
	revoked, err := found.(RuntimeOwnershipSession).RuntimeRevoked(t.Context())
	require.NoError(t, err)
	require.True(t, revoked)
	path, err := restarted.file(sess.Flow(), sess.Id(), FsFileRuntimeRevocation)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("future-secret-tombstone"), 0600))
	require.ErrorIs(t, restarted.RevokeRuntimeSession(t.Context(), sess.Flow(), sess.Id()), ErrInvalidRuntimeOwnership)
	preserved, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "future-secret-tombstone", string(preserved))
	revoked, err = found.(RuntimeOwnershipSession).RuntimeRevoked(t.Context())
	require.True(t, revoked)
	require.ErrorIs(t, err, ErrInvalidRuntimeOwnership)
}

func TestFsRuntimeOwnershipNeverImportsAnEstablishedLegacySession(t *testing.T) {
	for _, established := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "established"}[established], func(t *testing.T) {
			repo, _ := newAssociationRepository(t)
			sess, err := repo.Create(t.Context(), "work", associationRemote("alice"), nil)
			require.NoError(t, err)
			missing, err := sess.(RuntimeOwnershipSession).RuntimeOwnership(t.Context())
			require.NoError(t, err)
			require.Nil(t, missing, "reading a legacy session never assigns it to the current runtime")
			state := runtimeOwnershipTestState(t)
			if established {
				require.NoError(t, sess.SetEnvironmentToken(t.Context(), []byte("existing-backend")))
			}
			found, err := repo.FindBy(WithRuntimeOwnership(t.Context(), state.Flows["work"]), "work", sess.Id(), nil)
			require.NoError(t, err)
			missing, err = found.(RuntimeOwnershipSession).RuntimeOwnership(t.Context())
			require.NoError(t, err)
			require.Nil(t, missing, "neither lookup nor its context can import an unbound legacy session")
		})
	}
}

func TestFsRuntimeOwnershipRejectsCopiedIdentityAndProtectsCorruptMetadata(t *testing.T) {
	repo, _ := newAssociationRepository(t)
	state := runtimeOwnershipTestState(t)
	first, err := repo.Create(WithRuntimeOwnership(t.Context(), state.Flows["work"]), "work", associationRemote("alice"), nil)
	require.NoError(t, err)
	second, err := repo.Create(t.Context(), "work", associationRemote("alice"), nil)
	require.NoError(t, err)
	firstPath, err := repo.file("work", first.Id(), FsFileRuntimeOwnership)
	require.NoError(t, err)
	secondPath, err := repo.file("work", second.Id(), FsFileRuntimeOwnership)
	require.NoError(t, err)
	raw, err := os.ReadFile(firstPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(secondPath, raw, 0600))
	cleanup := true
	opts := &FindOpts{AutoCleanUpAllowed: &cleanup}
	_, err = repo.FindBy(t.Context(), "work", second.Id(), opts)
	require.ErrorIs(t, err, ErrInvalidRuntimeOwnership)
	metadata := filepath.Join(filepath.Dir(secondPath), FsFileSession)
	require.NoError(t, os.WriteFile(metadata, []byte("broken metadata"), 0600))
	_, err = repo.FindBy(t.Context(), "work", second.Id(), opts)
	require.ErrorIs(t, err, ErrInvalidRuntimeOwnership)
	require.FileExists(t, metadata)
	require.FileExists(t, secondPath)
}

func TestFsRuntimeMetadataSurvivesAutomaticCleanupAndAssociationCreation(t *testing.T) {
	repo, _ := newAssociationRepository(t)
	state := runtimeOwnershipTestState(t)
	_, err := repo.RuntimeKey(t.Context())
	require.NoError(t, err)
	require.NoError(t, repo.CommitRuntimeState(t.Context(), "", *state).Err)
	ctx := WithRuntimeOwnership(t.Context(), state.Flows["work"])
	sess, created, err := repo.ResolveAssociatedSession(ctx, associationRequestFor(t, "one"))
	require.NoError(t, err)
	require.True(t, created)
	owner, err := sess.(RuntimeOwnershipSession).RuntimeOwnership(ctx)
	require.NoError(t, err)
	require.True(t, owner.Matches(state.Flows["work"]))
	cleanup := true
	require.NoError(t, repo.FindAll(t.Context(), func(context.Context, Session) (bool, error) { return true, nil }, &FindOpts{AutoCleanUpAllowed: &cleanup}))
	require.FileExists(t, repo.runtimeFile(FsFileRuntimeKey))
	require.FileExists(t, repo.runtimeFile(FsFileRuntimeState))
	_, err = repo.FindBy(t.Context(), "work", sess.Id(), nil)
	require.NoError(t, err)
	digests := runtimeOwnershipTestDigests()
	digests["work"] = configuration.RuntimeFlowDigests{Environment: strings.Repeat("c", 64), Owner: strings.Repeat("d", 64)}
	next, err := AdvanceRuntimeState(state, digests)
	require.NoError(t, err)
	// AssociatedRepository's caller still owns eligibility checks. A creation
	// context cannot overwrite the owner of an existing selected session.
	same, created, err := repo.ResolveAssociatedSession(WithRuntimeOwnership(t.Context(), next.Flows["work"]), associationRequestFor(t, "one"))
	require.NoError(t, err)
	require.False(t, created)
	retained, err := same.(RuntimeOwnershipSession).RuntimeOwnership(t.Context())
	require.NoError(t, err)
	require.Equal(t, owner, retained)
}

func TestFsRuntimeMissingKeyOrMalformedStateIsNotReinitialized(t *testing.T) {
	for _, mode := range []string{"missing-key", "corrupt", "future", "duplicate", "case", "null", "unicode", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			repo, _ := newAssociationRepository(t)
			_, err := repo.RuntimeKey(t.Context())
			require.NoError(t, err)
			state := runtimeOwnershipTestState(t)
			require.NoError(t, repo.CommitRuntimeState(t.Context(), "", *state).Err)
			path := repo.runtimeFile(FsFileRuntimeState)
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			switch mode {
			case "missing-key":
				require.NoError(t, os.Remove(repo.runtimeFile(FsFileRuntimeKey)))
				_, err := repo.RuntimeKey(t.Context())
				require.ErrorIs(t, err, ErrInvalidRuntimeState)
				return
			case "corrupt":
				raw = []byte("secret-never-log")
			case "future":
				raw = []byte(strings.Replace(string(raw), RuntimeStateSchema, "future-format", 1))
			case "duplicate":
				raw = []byte(strings.Replace(string(raw), `"flows":{`, `"flows":{},"flows":{`, 1))
			case "case":
				raw = []byte(strings.Replace(string(raw), `"schema"`, `"Schema"`, 1))
			case "null":
				raw = []byte(strings.Replace(string(raw), `"flows":{`, `"flows":null,"discard":{`, 1))
			case "unicode":
				raw = []byte(strings.Replace(string(raw), `"work"`, `"\ud800"`, 1))
			case "oversized":
				raw = []byte(strings.Repeat("x", maximumRuntimeStateBytes+1))
			}
			require.NoError(t, os.WriteFile(path, raw, 0600))
			_, err = repo.RuntimeState(t.Context())
			require.ErrorIs(t, err, ErrInvalidRuntimeState)
			require.NotContains(t, err.Error(), "secret-never-log")
			result := repo.CommitRuntimeState(t.Context(), state.Revision, *runtimeOwnershipTestState(t))
			require.False(t, result.Published)
			require.Error(t, result.Err)
			preserved, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, raw, preserved)
		})
	}
}

func TestFsRuntimeInvalidCreationDoesNotLeaveAPartialSession(t *testing.T) {
	repo, _ := newAssociationRepository(t)
	sess, err := repo.Create(WithRuntimeOwnership(t.Context(), RuntimeFlow{}), "work", associationRemote("alice"), nil)
	require.Error(t, err)
	require.Nil(t, sess)
	count := 0
	require.NoError(t, repo.FindAll(t.Context(), func(context.Context, Session) (bool, error) { count++; return true, nil }, nil))
	require.Zero(t, count)
}

func TestRuntimeJSONRejectsNestedDuplicateAndTrailingDocuments(t *testing.T) {
	state := runtimeOwnershipTestState(t)
	raw, err := json.Marshal(state)
	require.NoError(t, err)
	for _, bad := range []string{
		string(raw) + `{}`,
		strings.Replace(string(raw), `"owner":`, `"owner":"`+strings.Repeat("e", 64)+`","owner":`, 1),
		strings.Replace(string(raw), `"environmentDigest":`, `"EnvironmentDigest":`, 1),
	} {
		var decoded RuntimeState
		require.Error(t, strictRuntimeJSON([]byte(bad), &decoded))
	}
}

func TestFsRuntimeMetadataDoesNotReserveValidFlowNames(t *testing.T) {
	repo, _ := newAssociationRepository(t)
	_, err := repo.RuntimeKey(t.Context())
	require.NoError(t, err)
	for _, name := range []configuration.FlowName{FsFileRuntimeKey, FsFileRuntimeState, FsFileRuntimePending} {
		_, err := repo.Create(t.Context(), name, associationRemote("alice"), nil)
		require.NoError(t, err)
	}
	count := 0
	require.NoError(t, repo.FindAll(t.Context(), func(context.Context, Session) (bool, error) { count++; return true, nil }, nil))
	require.Equal(t, 3, count)
}
