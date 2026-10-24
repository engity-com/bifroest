package session

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

type associationRemote string

func (this associationRemote) User() string   { return string(this) }
func (associationRemote) Host() bnet.Host     { return bnet.MustNewHost("127.0.0.1") }
func (this associationRemote) String() string { return string(this) + "@127.0.0.1" }

func newAssociationRepository(t *testing.T) (*FsRepository, *configuration.SessionFs) {
	t.Helper()
	conf := newFsRepositoryTestConfiguration(t)
	conf.IdleTimeout.SetNative(time.Hour)
	repository, err := NewFsRepository(context.Background(), conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	return repository, conf
}

func associationRequestFor(t *testing.T, user string) AssociationRequest {
	t.Helper()
	target := associationTestTarget(t, user)
	return AssociationRequest{Flow: "work", Identity: associationTestIdentity(), Remote: associationRemote("ssh-client-name"), AuthorizationToken: []byte("opaque-auth-token"), ResolveTarget: func(context.Context, Reference) (Target, error) { return target, nil }}
}

func TestAssociatedSessionSurvivesRestartAndDoesNotOverwriteTokens(t *testing.T) {
	repository, conf := newAssociationRepository(t)
	ctx := context.Background()
	request := associationRequestFor(t, "target-account")
	first, created, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	require.True(t, created)
	association, err := AssociationOf(ctx, first)
	require.NoError(t, err)
	require.True(t, association.SameSubject(request.Identity))
	require.NoError(t, first.SetEnvironmentToken(ctx, []byte(`{"concreteContainerId":"already-running-container"}`)))
	_, err = first.NotifyLastAccess(ctx, request.Remote, StateAuthorized)
	require.NoError(t, err)
	request.Remote = associationRemote("") // HTTP's disabled name prompt must not fragment this identity.
	request.Identity.Principal = "different-principal-mapping"
	request.AuthorizationToken = []byte("fresh-login-token-must-not-clobber-refresh-state")
	second, created, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, first.Id(), second.Id())
	token, err := second.AuthorizationToken(ctx)
	require.NoError(t, err)
	require.Equal(t, "opaque-auth-token", string(token))
	environment, err := second.EnvironmentToken(ctx)
	require.NoError(t, err)
	require.Contains(t, string(environment), "already-running-container")
	require.NoError(t, repository.Close())
	restarted, err := NewFsRepository(ctx, conf)
	require.NoError(t, err)
	defer restarted.Close()
	third, created, err := restarted.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, first.Id(), third.Id())
	info, err := third.Info(ctx)
	require.NoError(t, err)
	createdInfo, err := info.Created(ctx)
	require.NoError(t, err)
	require.Equal(t, "ssh-client-name", createdInfo.Remote().User(), "client metadata is not rewritten into a normalized principal")
}

func TestAssociationBindingIsImmutableAndIndependentOfStaleMetadata(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	ctx := context.Background()
	sess, err := repository.Create(ctx, "work", associationRemote("old-client"), nil)
	require.NoError(t, err)
	stale, err := repository.FindBy(ctx, "work", sess.Id(), nil)
	require.NoError(t, err)
	association, err := NewAssociation(associationTestIdentity(), associationTestTarget(t, "target"))
	require.NoError(t, err)
	binder := sess.(AssociationBinder)
	require.NoError(t, binder.BindSessionAssociation(ctx, association))
	require.NoError(t, stale.(AssociationBinder).BindSessionAssociation(ctx, association))
	other := association
	other.Target = associationTestTarget(t, "different-target")
	require.ErrorIs(t, binder.BindSessionAssociation(ctx, other), ErrAssociationConflict)
	_, err = stale.NotifyLastAccess(ctx, associationRemote(""), StateAuthorized)
	require.NoError(t, err)
	require.NoError(t, stale.SetAuthorizationToken(ctx, []byte("updated")))
	stored, err := AssociationOf(ctx, stale)
	require.NoError(t, err)
	require.Equal(t, association, *stored)
	_, err = sess.Dispose(ctx)
	require.NoError(t, err)
	require.Error(t, binder.BindSessionAssociation(ctx, association))
}

func TestAssociationSeparatesSubjectsFlowsAndEffectiveTargets(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	ctx := context.Background()
	request := associationRequestFor(t, "one")
	first, _, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	cases := []AssociationRequest{associationRequestFor(t, "two"), associationRequestFor(t, "one"), associationRequestFor(t, "one"), associationRequestFor(t, "one")}
	cases[1].Identity.Subject = "another-subject"
	cases[2].Identity.Issuer = "https://another-issuer.example.org"
	cases[3].Flow = "another-flow"
	seen := map[Id]bool{first.Id(): true}
	for _, request := range cases {
		found, created, err := repository.ResolveAssociatedSession(ctx, request)
		require.NoError(t, err)
		require.True(t, created)
		require.False(t, seen[found.Id()])
		seen[found.Id()] = true
	}
}

func TestAssociationDoesNotClaimLegacyOrAnonymousSessions(t *testing.T) {
	repository, conf := newAssociationRepository(t)
	ctx := context.Background()
	request := associationRequestFor(t, "one")
	legacy, err := repository.Create(ctx, request.Flow, request.Remote, request.AuthorizationToken)
	require.NoError(t, err)
	selected, created, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, legacy.Id(), selected.Id())
	old, err := repository.FindBy(ctx, request.Flow, legacy.Id(), nil)
	require.NoError(t, err)
	binding, err := AssociationOf(ctx, old)
	require.NoError(t, err)
	require.Nil(t, binding)
	request.Identity = authentication.Anonymous()
	request.Remote = associationRemote("alice")
	_, _, err = repository.ResolveAssociatedSession(ctx, request)
	require.ErrorIs(t, err, ErrAnonymousAssociation)
	require.DirExists(t, conf.Storage)
}

func TestConcurrentAssociationUsesOneSessionAndCandidateSpecificTarget(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	request := associationRequestFor(t, "one")
	request.ResolveTarget = func(_ context.Context, candidate Reference) (Target, error) {
		return NewTarget("kubernetes", map[string]string{"cluster": "test", "namespace": "work", "name": "bifroest-" + candidate.Id.String(), "user": "1000"})
	}
	const amount = 24
	ids := make(chan Id, amount)
	failures := make(chan error, amount)
	var created atomic.Int32
	var wait sync.WaitGroup
	for i := 0; i < amount; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			found, isNew, err := repository.ResolveAssociatedSession(context.Background(), request)
			if err != nil {
				failures <- err
				return
			}
			if isNew {
				created.Add(1)
			}
			ids <- found.Id()
		}()
	}
	wait.Wait()
	close(ids)
	close(failures)
	for err := range failures {
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), created.Load())
	var expected Id
	for id := range ids {
		if expected.IsZero() {
			expected = id
		}
		require.Equal(t, expected, id)
	}
	repository.associationMutex.Lock()
	remaining := len(repository.associationLocks)
	repository.associationMutex.Unlock()
	require.Zero(t, remaining)
}

func TestAssociationWaitCancellationDoesNotCancelItsOwner(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	request := associationRequestFor(t, "one")
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	target := associationTestTarget(t, "one")
	request.ResolveTarget = func(ctx context.Context, _ Reference) (Target, error) {
		close(started)
		select {
		case <-release:
			return target, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	done := make(chan error, 1)
	go func() { _, _, err := repository.ResolveAssociatedSession(context.Background(), request); done <- err }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := repository.ResolveAssociatedSession(ctx, request)
	require.ErrorIs(t, err, context.Canceled)
	unblock()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("owner did not finish")
	}
}

func TestMalformedAssociationIsPreservedDespiteAutoCleanup(t *testing.T) {
	for _, bad := range []string{`{"schema":"newer-format"}`, `{"subject":"secret-never-log"}`, strings.Repeat("x", maximumAssociationBytes+1)} {
		repository, _ := newAssociationRepository(t)
		request := associationRequestFor(t, "one")
		sess, _, err := repository.ResolveAssociatedSession(context.Background(), request)
		require.NoError(t, err)
		path, err := repository.file(request.Flow, sess.Id(), FsFileAssociation)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, []byte(bad), 0600))
		cleanup := true
		_, err = repository.FindBy(context.Background(), request.Flow, sess.Id(), &FindOpts{AutoCleanUpAllowed: &cleanup})
		require.ErrorIs(t, err, ErrInvalidAssociation)
		require.NotContains(t, err.Error(), "secret-never-log")
		stored, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, bad, string(stored))
		require.FileExists(t, filepath.Join(filepath.Dir(path), FsFileSession))
		_, _, err = repository.ResolveAssociatedSession(context.Background(), request)
		require.ErrorIs(t, err, ErrInvalidAssociation)
	}
}

func TestAssociationRejectsExpiredDisposedIncompatibleAndReadOnlyCandidates(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	ctx := context.Background()
	request := associationRequestFor(t, "one")
	first, _, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	request.Compatible = func(_ context.Context, candidate Session) (bool, error) { return candidate.Id() != first.Id(), nil }
	second, created, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, first.Id(), second.Id())
	_, err = second.Dispose(ctx)
	require.NoError(t, err)
	request.Compatible = nil
	lastAccessed, err := repository.file(request.Flow, first.Id(), FsFileLastAccessed)
	require.NoError(t, err)
	past := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(lastAccessed, past, past))
	third, created, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, first.Id(), third.Id())
	require.NotEqual(t, second.Id(), third.Id())
	request.Compatible = func(context.Context, Session) (bool, error) {
		return false, errors.New("compatibility inspection failed")
	}
	_, _, err = repository.ResolveAssociatedSession(ctx, request)
	require.ErrorContains(t, err, "compatibility inspection failed")
	request.Compatible = nil
	require.NoError(t, repository.Close())
	_, _, err = repository.ResolveAssociatedSession(ctx, request)
	require.Error(t, err)
}

func TestAssociationCleanupAllowlistAndCanonicalEncoding(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	ctx := context.Background()
	request := associationRequestFor(t, "one")
	sess, _, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	cleanup := true
	_, err = repository.FindBy(ctx, request.Flow, sess.Id(), &FindOpts{AutoCleanUpAllowed: &cleanup})
	require.NoError(t, err)
	association, err := AssociationOf(ctx, sess)
	require.NoError(t, err)
	require.NotNil(t, association)
	path, err := repository.file(request.Flow, sess.Id(), FsFileAssociation)
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.Len(t, fields, 4)
	require.NotContains(t, string(raw), "opaque-auth-token")
}

func TestAssociationCannotClaimAnEstablishedLegacySession(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	ctx := context.Background()
	association, err := NewAssociation(associationTestIdentity(), associationTestTarget(t, "one"))
	require.NoError(t, err)
	for _, kind := range []string{"authorized", "environment", "active connection"} {
		sess, err := repository.Create(ctx, "work", associationRemote("alice"), nil)
		require.NoError(t, err)
		switch kind {
		case "authorized":
			_, err = sess.NotifyLastAccess(ctx, associationRemote("alice"), StateAuthorized)
			require.NoError(t, err)
		case "environment":
			require.NoError(t, sess.SetEnvironmentToken(ctx, []byte("existing resource")))
		case "active connection":
			interceptor, err := sess.ConnectionInterceptor(ctx)
			require.NoError(t, err)
			defer interceptor.Close()
		}
		require.ErrorIs(t, sess.(AssociationBinder).BindSessionAssociation(ctx, association), ErrAssociationConflict)
		stored, err := AssociationOf(ctx, sess)
		require.NoError(t, err)
		require.Nil(t, stored)
	}
}

func TestAssociationPreventsCleanupWhenMainMetadataIsBroken(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	ctx := context.Background()
	request := associationRequestFor(t, "one")
	sess, _, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	path, err := repository.file(request.Flow, sess.Id(), FsFileSession)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("invalid main metadata"), 0600))
	cleanup := true
	_, err = repository.FindBy(ctx, request.Flow, sess.Id(), &FindOpts{AutoCleanUpAllowed: &cleanup})
	require.ErrorIs(t, err, ErrInvalidAssociation)
	require.FileExists(t, path)
	require.FileExists(t, filepath.Join(filepath.Dir(path), FsFileAssociation))
	require.NoError(t, os.Remove(path))
	_, err = repository.FindBy(ctx, request.Flow, sess.Id(), &FindOpts{AutoCleanUpAllowed: &cleanup})
	require.ErrorIs(t, err, ErrInvalidAssociation)
	_, _, err = repository.ResolveAssociatedSession(ctx, request)
	require.ErrorIs(t, err, ErrInvalidAssociation)
	require.FileExists(t, filepath.Join(filepath.Dir(path), FsFileAssociation))
}

func TestAssociationDoesNotFollowSidecarSymlinks(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	ctx := context.Background()
	request := associationRequestFor(t, "one")
	sess, _, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	path, err := repository.file(request.Flow, sess.Id(), FsFileAssociation)
	require.NoError(t, err)
	require.NoError(t, os.Rename(path, path+".real"))
	if err := os.Symlink(path+".real", path); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	_, err = repository.FindBy(ctx, request.Flow, sess.Id(), nil)
	require.ErrorIs(t, err, ErrInvalidAssociation)
	require.FileExists(t, path+".real")
}

func TestAssociationRechecksDisposalAfterCompatibilityCallback(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	ctx := context.Background()
	request := associationRequestFor(t, "one")
	first, _, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	request.Compatible = func(ctx context.Context, candidate Session) (bool, error) {
		_, err := candidate.Dispose(ctx)
		return true, err
	}
	second, created, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, first.Id(), second.Id())
}

func TestAssociatedCreationCannotOverwriteAnExistingSessionDirectory(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	ctx := context.Background()
	request := associationRequestFor(t, "one")
	first, _, err := repository.ResolveAssociatedSession(ctx, request)
	require.NoError(t, err)
	before, err := first.AuthorizationToken(ctx)
	require.NoError(t, err)
	repository.mutex.Lock()
	_, err = repository.create(ctx, request.Flow, request.Remote, []byte("must not replace"), first.Id(), nil)
	repository.mutex.Unlock()
	require.Error(t, err)
	stillThere, err := repository.FindBy(ctx, request.Flow, first.Id(), nil)
	require.NoError(t, err)
	after, err := stillThere.AuthorizationToken(ctx)
	require.NoError(t, err)
	require.Equal(t, before, after)
	association, err := AssociationOf(ctx, stillThere)
	require.NoError(t, err)
	require.NotNil(t, association)
}

func TestAssociationResolverRechecksCloseAndCancellationBeforeCreation(t *testing.T) {
	for _, mode := range []string{"cancel", "close", "target error"} {
		t.Run(mode, func(t *testing.T) {
			repository, conf := newAssociationRepository(t)
			request := associationRequestFor(t, "one")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			target := associationTestTarget(t, "one")
			request.ResolveTarget = func(context.Context, Reference) (Target, error) {
				switch mode {
				case "cancel":
					cancel()
				case "close":
					if err := repository.Close(); err != nil {
						return "", err
					}
				case "target error":
					return "", errors.New("cannot resolve effective target")
				}
				return target, nil
			}
			_, _, err := repository.ResolveAssociatedSession(ctx, request)
			require.Error(t, err)
			if mode == "cancel" {
				require.ErrorIs(t, err, context.Canceled)
			}
			require.NoDirExists(t, conf.Storage)
		})
	}
}

type associationUnsupportedRepository struct{ CloseableRepository }

func TestAssociationFacadeForwardsOnlyToSupportingRepositories(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	facade := &FacadeRepository{CloseableRepository: repository}
	_, created, err := facade.ResolveAssociatedSession(context.Background(), associationRequestFor(t, "one"))
	require.NoError(t, err)
	require.True(t, created)
	unsupported := &FacadeRepository{CloseableRepository: associationUnsupportedRepository{}}
	_, _, err = unsupported.ResolveAssociatedSession(context.Background(), associationRequestFor(t, "one"))
	require.ErrorIs(t, err, ErrAssociationUnavailable)
}

func TestAssociatedSessionCreationPreviewUsesExactPersistedMetadata(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	request := associationRequestFor(t, "one")
	var at time.Time
	request.ResolveTarget = func(ctx context.Context, ref Reference) (Target, error) {
		require.NotNil(t, ref.Created)
		at = ref.Created.At()
		return NewTarget("test", map[string]string{"at": at.UTC().Format(time.RFC3339Nano), "user": ref.Created.Remote().User()})
	}
	first, created, err := repository.ResolveAssociatedSession(t.Context(), request)
	require.NoError(t, err)
	require.True(t, created)
	info, err := first.Info(t.Context())
	require.NoError(t, err)
	metadata, err := info.Created(t.Context())
	require.NoError(t, err)
	require.Equal(t, at, metadata.At())
	request.Remote = associationRemote("")
	second, created, err := repository.ResolveAssociatedSession(t.Context(), request)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, first.Id(), second.Id())
}
