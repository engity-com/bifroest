package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
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
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/browserauth"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func browserBindingFixture(t *testing.T) (*FsRepository, *configuration.SessionFs, *fs, BrowserBindingSpec) {
	t.Helper()
	conf := newFsRepositoryTestConfiguration(t)
	conf.IdleTimeout.SetNative(0)
	conf.MaxTimeout.SetNative(0)
	conf.MaxConnections = 1
	repository, err := NewFsRepository(t.Context(), conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	sess, err := repository.Create(t.Context(), "work", associationRemote(""), []byte("authorization-must-not-change"))
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spec := BrowserBindingSpec{Origin: "https://app.example.org:8443", Slug: "Work", Identity: associationTestIdentity(), Target: associationTestTarget(t, "account"), User: "", PublicKey: browserauth.PublicKey(base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y)))}
	return repository, conf, sess.(*fs), spec
}

func TestBrowserBindingSurvivesRestartWithoutTouchingSessionOrSshKeys(t *testing.T) {
	repository, conf, sess, spec := browserBindingFixture(t)
	ctx := t.Context()
	now := time.Now().UTC()
	require.NoError(t, sess.SetEnvironmentToken(ctx, []byte(`{"containerId":"keep-this-workload"}`)))
	path, _ := repository.file(sess.flow, sess.id, FsFileLastAccessed)
	before, err := os.Stat(path)
	require.NoError(t, err)
	binding, err := sess.createBrowserBinding(ctx, spec, 6*time.Hour, now)
	require.NoError(t, err)
	require.True(t, validBrowserBindingID(binding.ID))
	require.EqualValues(t, 1, binding.Revision)
	_, err = sess.useBrowserBinding(ctx, binding.ID, 1, 6*time.Hour, now.Add(time.Hour))
	require.NoError(t, err)
	after, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, before.ModTime(), after.ModTime())
	parsed, err := spec.PublicKey.Parse()
	require.NoError(t, err)
	sshKey, err := ssh.NewPublicKey(parsed)
	require.NoError(t, err)
	has, err := sess.HasPublicKey(ctx, sshKey)
	require.NoError(t, err)
	require.False(t, has, "a browser key must never register an SSH remembered key")
	require.NoError(t, repository.Close())
	restarted, err := NewFsRepository(ctx, conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.Close()) })
	current, err := restarted.FindBy(ctx, sess.flow, sess.id, nil)
	require.NoError(t, err)
	bindings, err := current.(BrowserBindingSession).BrowserBindings(ctx)
	require.NoError(t, err)
	require.Len(t, bindings, 1)
	require.Equal(t, spec, bindings[0].BrowserBindingSpec)
	require.Equal(t, binding.ID, bindings[0].ID)
	require.EqualValues(t, 2, bindings[0].Revision)
	token, err := current.AuthorizationToken(ctx)
	require.NoError(t, err)
	require.Equal(t, "authorization-must-not-change", string(token))
	env, err := current.EnvironmentToken(ctx)
	require.NoError(t, err)
	require.Contains(t, string(env), "keep-this-workload")
	info, err := current.Info(ctx)
	require.NoError(t, err)
	require.Equal(t, StateNew, info.State())
}

func TestBrowserBindingUsesSlidingIdleAndCannotReviveExpiredOrStaleRevision(t *testing.T) {
	_, _, sess, spec := browserBindingFixture(t)
	ctx := t.Context()
	now := time.Now().UTC()
	binding, err := sess.createBrowserBinding(ctx, spec, 6*time.Hour, now)
	require.NoError(t, err)
	for revision := uint64(1); revision <= 3; revision++ {
		used, err := sess.useBrowserBinding(ctx, binding.ID, revision, 6*time.Hour, now.Add(time.Duration(revision)*5*time.Hour))
		require.NoError(t, err)
		require.Equal(t, now.Add(time.Duration(revision*5+6)*time.Hour), used.ExpiresAt)
	}
	_, err = sess.useBrowserBinding(ctx, binding.ID, 3, 6*time.Hour, now.Add(16*time.Hour))
	require.ErrorIs(t, err, ErrBrowserBindingDenied)
	_, err = sess.useBrowserBinding(ctx, binding.ID, 4, 6*time.Hour, now.Add(21*time.Hour))
	require.ErrorIs(t, err, ErrBrowserBindingDenied)
	_, err = sess.useBrowserBinding(ctx, binding.ID, 4, 24*time.Hour, now.Add(22*time.Hour))
	require.ErrorIs(t, err, ErrBrowserBindingDenied, "a larger configured timeout cannot revive the persisted expired grant")
	bindings, err := sess.BrowserBindings(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 4, bindings[0].Revision)
	_, err = sess.useBrowserBinding(ctx, binding.ID, 4, time.Hour, now.Add(16*time.Hour))
	require.ErrorIs(t, err, ErrBrowserBindingDenied, "a shorter timeout additionally caps eligibility")
	_, err = sess.useBrowserBinding(ctx, binding.ID, 4, 24*time.Hour, now.Add(17*time.Hour))
	require.ErrorIs(t, err, ErrBrowserBindingDenied, "an observed shorter-policy expiry remains expired after a later increase")
}

func TestBrowserBindingExpiryAndRevokePreserveConnectionsSiblingAndSession(t *testing.T) {
	_, _, sess, spec := browserBindingFixture(t)
	ctx := t.Context()
	now := time.Now().UTC()
	lease, err := sess.ConnectionInterceptor(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, lease.Close()) })
	one, err := sess.createBrowserBinding(ctx, spec, time.Minute, now)
	require.NoError(t, err)
	two, err := sess.createBrowserBinding(ctx, spec, 6*time.Hour, now)
	require.NoError(t, err)
	_, err = sess.useBrowserBinding(ctx, one.ID, 1, time.Minute, now.Add(time.Minute))
	require.ErrorIs(t, err, ErrBrowserBindingDenied)
	require.NoError(t, sess.RevokeBrowserBinding(ctx, one.ID))
	require.NoError(t, sess.RevokeBrowserBinding(ctx, one.ID))
	require.True(t, sess.HasActiveConnections())
	_, result, err := lease.(ActivityInterceptor).Check(ctx)
	require.NoError(t, err)
	require.NotEqual(t, ConnectionInterceptorResultDisposed, result)
	_, err = sess.ConnectionInterceptor(ctx)
	require.ErrorIs(t, err, ErrMaxConnectionsPerSessionReached)
	_, err = sess.useBrowserBinding(ctx, two.ID, 1, 6*time.Hour, now.Add(time.Hour))
	require.NoError(t, err)
	info, err := sess.Info(ctx)
	require.NoError(t, err)
	require.NotEqual(t, StateDisposed, info.State())
	_, err = sess.useBrowserBinding(ctx, one.ID, 1, 6*time.Hour, now.Add(time.Hour))
	require.ErrorIs(t, err, ErrBrowserBindingDenied)
}

func TestBrowserBindingAtomicUseAndConcurrentRevocation(t *testing.T) {
	_, _, sess, spec := browserBindingFixture(t)
	ctx := t.Context()
	binding, err := sess.CreateBrowserBinding(ctx, spec, time.Hour)
	require.NoError(t, err)
	var winners atomic.Int32
	var group sync.WaitGroup
	for range 24 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := sess.UseBrowserBinding(ctx, binding.ID, 1, time.Hour)
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrBrowserBindingDenied) {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	require.EqualValues(t, 1, winners.Load())
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := sess.UseBrowserBinding(ctx, binding.ID, 2, time.Hour)
			if err != nil && !errors.Is(err, ErrBrowserBindingDenied) {
				t.Error(err)
			}
		}()
	}
	require.NoError(t, sess.RevokeBrowserBinding(ctx, binding.ID))
	group.Wait()
	bindings, err := sess.BrowserBindings(ctx)
	require.NoError(t, err)
	require.Empty(t, bindings)
	_, err = sess.UseBrowserBinding(ctx, binding.ID, 2, time.Hour)
	require.ErrorIs(t, err, ErrBrowserBindingDenied)
}

func TestBrowserBindingUseChecksExpiryAfterWaitingForTheRepositoryLock(t *testing.T) {
	repository, _, sess, spec := browserBindingFixture(t)
	binding, err := sess.CreateBrowserBinding(t.Context(), spec, 80*time.Millisecond)
	require.NoError(t, err)
	repository.mutex.Lock()
	entered := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(entered)
		_, err := sess.UseBrowserBinding(t.Context(), binding.ID, 1, 80*time.Millisecond)
		result <- err
	}()
	<-entered
	time.Sleep(120 * time.Millisecond)
	repository.mutex.Unlock()
	select {
	case err := <-result:
		require.ErrorIs(t, err, ErrBrowserBindingDenied)
	case <-time.After(time.Second):
		t.Fatal("binding use did not finish")
	}
}

func TestBrowserBindingsRespectSessionExpiryDisposalAndClosedWriter(t *testing.T) {
	for _, mode := range []string{"idle", "maximum", "disposed", "closed", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			repository, conf, sess, spec := browserBindingFixture(t)
			ctx := t.Context()
			now := time.Now().UTC()
			binding, err := sess.createBrowserBinding(ctx, spec, 6*time.Hour, now)
			require.NoError(t, err)
			useCtx := ctx
			switch mode {
			case "idle":
				conf.IdleTimeout.SetNative(time.Millisecond)
				now = now.Add(time.Second)
			case "maximum":
				conf.MaxTimeout.SetNative(time.Millisecond)
				now = now.Add(time.Second)
			case "disposed":
				_, err := sess.Dispose(ctx)
				require.NoError(t, err)
			case "closed":
				require.NoError(t, repository.Close())
			case "canceled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				useCtx = canceled
			}
			_, err = sess.useBrowserBinding(useCtx, binding.ID, 1, 6*time.Hour, now)
			require.Error(t, err)
			_, err = sess.createBrowserBinding(useCtx, spec, 6*time.Hour, now)
			require.Error(t, err)
			bindings, err := sess.BrowserBindings(ctx)
			require.NoError(t, err)
			require.EqualValues(t, 1, bindings[0].Revision)
		})
	}
}

func TestBrowserBindingOwnerTargetScopeAndAnonymousSessionsStaySeparate(t *testing.T) {
	repository, _, sess, spec := browserBindingFixture(t)
	ctx := t.Context()
	association, err := NewAssociation(spec.Identity, spec.Target)
	require.NoError(t, err)
	require.NoError(t, sess.BindSessionAssociation(ctx, association))
	for _, field := range []string{"issuer", "subject", "target", "anonymous"} {
		other := spec
		switch field {
		case "issuer":
			other.Identity.Issuer = "other"
		case "subject":
			other.Identity.Subject = "other"
		case "target":
			other.Target = associationTestTarget(t, "other")
		case "anonymous":
			other.Identity = authentication.Anonymous()
		}
		_, err := sess.CreateBrowserBinding(ctx, other, time.Hour)
		require.ErrorIs(t, err, ErrBrowserBindingDenied)
	}
	for _, scope := range []struct{ origin, slug string }{{"https://app.example.org", "Work"}, {"https://other.example.org", "Work"}, {"https://app.example.org:8443", "work"}} {
		other := spec
		other.Origin = scope.origin
		other.Slug = scope.slug
		binding, err := sess.CreateBrowserBinding(ctx, other, time.Hour)
		require.NoError(t, err)
		require.Equal(t, other, binding.BrowserBindingSpec)
	}
	first, err := repository.Create(ctx, "work", associationRemote(""), nil)
	require.NoError(t, err)
	second, err := repository.Create(ctx, "work", associationRemote(""), nil)
	require.NoError(t, err)
	spec.Identity = authentication.Anonymous()
	one, err := first.(BrowserBindingSession).CreateBrowserBinding(ctx, spec, time.Hour)
	require.NoError(t, err)
	_, err = second.(BrowserBindingSession).UseBrowserBinding(ctx, one.ID, 1, time.Hour)
	require.ErrorIs(t, err, ErrBrowserBindingDenied)
	require.Nil(t, mustAssociation(t, first), "browser possession does not claim anonymous shared ownership")
	require.ErrorIs(t, first.(AssociationBinder).BindSessionAssociation(ctx, association), ErrAssociationConflict, "a new ownership record cannot claim an existing anonymous browser session")
}

func mustAssociation(t *testing.T, sess Session) *Association {
	t.Helper()
	value, err := AssociationOf(t.Context(), sess)
	require.NoError(t, err)
	return value
}

func TestBrowserBindingLimitsAndExpiredCapacity(t *testing.T) {
	_, _, sess, spec := browserBindingFixture(t)
	ctx := t.Context()
	now := time.Now().UTC()
	for range MaximumBrowserBindings {
		_, err := sess.createBrowserBinding(ctx, spec, time.Hour, now)
		require.NoError(t, err)
	}
	_, err := sess.createBrowserBinding(ctx, spec, time.Hour, now)
	require.ErrorIs(t, err, ErrBrowserBindingLimit)
	_, err = sess.createBrowserBinding(ctx, spec, time.Hour, now.Add(time.Hour))
	require.NoError(t, err)
	bindings, err := sess.BrowserBindings(ctx)
	require.NoError(t, err)
	require.Len(t, bindings, 1)
}

func TestBrowserBindingSidecarCannotBeCopiedToAnotherSession(t *testing.T) {
	repository, _, sess, spec := browserBindingFixture(t)
	_, err := sess.CreateBrowserBinding(t.Context(), spec, time.Hour)
	require.NoError(t, err)
	source, _ := repository.file(sess.flow, sess.id, FsFileBrowserBindings)
	raw, err := os.ReadFile(source)
	require.NoError(t, err)
	for _, flow := range []configuration.FlowName{"work", "other"} {
		other, err := repository.Create(t.Context(), flow, associationRemote(""), nil)
		require.NoError(t, err)
		dest, _ := repository.file(other.Flow(), other.Id(), FsFileBrowserBindings)
		require.NoError(t, os.WriteFile(dest, raw, 0600))
		_, err = other.(BrowserBindingSession).BrowserBindings(t.Context())
		require.ErrorIs(t, err, ErrInvalidBrowserBinding)
	}
}

func TestBrowserBindingStrictJsonPreservesCorruptFiles(t *testing.T) {
	repository, _, sess, spec := browserBindingFixture(t)
	ctx := t.Context()
	_, err := sess.CreateBrowserBinding(ctx, spec, time.Hour)
	require.NoError(t, err)
	path, _ := repository.file(sess.flow, sess.id, FsFileBrowserBindings)
	valid, err := os.ReadFile(path)
	require.NoError(t, err)
	var duplicate browserBindingsFile
	require.NoError(t, json.Unmarshal(valid, &duplicate))
	duplicate.Bindings = append(duplicate.Bindings, duplicate.Bindings[0])
	duplicateJSON, err := json.Marshal(duplicate)
	require.NoError(t, err)
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`null`), append(append([]byte(nil), valid...), []byte(` {}`)...), bytesReplace(valid, `"schema":`, `"Schema":`), bytesReplace(valid, `"bindings":`, `"unexpected":`), bytesReplace(valid, `"origin":`, `"origin":null,"origin":`), bytesReplace(valid, `"slug":"Work"`, `"slug":null`), bytesReplace(valid, `"user":""`, `"user":"\ud800"`), bytesReplace(valid, `"revision":1`, `"revision":1.0`), bytesReplace(valid, `"revision":1`, `"revision":0`), bytesReplace(valid, `"principal":`, `"Principal":`), bytesReplace(valid, `"principal":`, `"privateKey":"secret","principal":`), duplicateJSON, []byte(strings.Repeat("x", maximumBrowserBindingsBytes+1))} {
		require.NoError(t, os.WriteFile(path, raw, 0600))
		_, err := sess.BrowserBindings(ctx)
		require.ErrorIs(t, err, ErrInvalidBrowserBinding)
		_, err = sess.CreateBrowserBinding(ctx, spec, time.Hour)
		require.ErrorIs(t, err, ErrInvalidBrowserBinding)
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, len(raw), len(after))
		require.Equal(t, string(raw), string(after))
	}
}

func bytesReplace(raw []byte, from, to string) []byte {
	return []byte(strings.Replace(string(raw), from, to, 1))
}

func TestBrowserBindingStateIsNotUnexpectedCleanupAndProtectsBrokenSession(t *testing.T) {
	for _, mode := range []string{"valid", "missing metadata", "broken metadata", "orphan"} {
		t.Run(mode, func(t *testing.T) {
			repository, _, sess, spec := browserBindingFixture(t)
			ctx := t.Context()
			_, err := sess.CreateBrowserBinding(ctx, spec, time.Hour)
			require.NoError(t, err)
			path, _ := repository.file(sess.flow, sess.id, FsFileBrowserBindings)
			metadata, _ := repository.file(sess.flow, sess.id, FsFileSession)
			allow := true
			opts := &FindOpts{AutoCleanUpAllowed: &allow}
			switch mode {
			case "valid":
				_, err := repository.FindBy(ctx, sess.flow, sess.id, opts)
				require.NoError(t, err)
			case "missing metadata":
				require.NoError(t, os.Remove(metadata))
				_, err := repository.FindBy(ctx, sess.flow, sess.id, opts)
				require.ErrorIs(t, err, ErrInvalidBrowserBinding)
			case "broken metadata":
				require.NoError(t, os.WriteFile(metadata, []byte(`{`), 0600))
				_, err := repository.FindBy(ctx, sess.flow, sess.id, opts)
				require.ErrorIs(t, err, ErrInvalidBrowserBinding)
			case "orphan":
				present, err := fsPathContainsEnvironmentToken(filepath.Dir(path))
				require.NoError(t, err)
				require.True(t, present)
			}
			require.FileExists(t, path)
		})
	}
}
