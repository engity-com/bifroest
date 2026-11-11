package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
)

func TestBrowserBindingCredentialIsImmutableStrictAndSeparateFromBrowserKey(t *testing.T) {
	repository, _, sess, spec := browserBindingFixture(t)
	primary, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	public, err := ssh.NewPublicKey(primary)
	require.NoError(t, err)
	spec.Credential = authentication.SessionCredential{Kind: "simple", Method: "public-key", PublicKey: base64.StdEncoding.EncodeToString(public.Marshal())}
	binding, err := sess.CreateBrowserBinding(t.Context(), spec, time.Hour)
	require.NoError(t, err)
	entries, err := sess.BrowserBindings(t.Context())
	require.NoError(t, err)
	require.Equal(t, binding, entries[0])
	require.NotEqual(t, string(spec.PublicKey), spec.Credential.PublicKey)
	path, _ := repository.file(sess.flow, sess.id, FsFileBrowserBindings)
	valid, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, raw := range []string{strings.Replace(string(valid), `"method":"public-key"`, `"method":null`, 1), strings.Replace(string(valid), `"kind":"simple"`, `"kind":"simple","kind":"none"`, 1), strings.Replace(string(valid), `"kind":"simple"`, `"Kind":"simple"`, 1), strings.Replace(string(valid), `"kind":"simple"`, `"privateKey":"secret","kind":"simple"`, 1)} {
		require.NoError(t, os.WriteFile(path, []byte(raw), 0600))
		_, err := sess.BrowserBindings(t.Context())
		require.ErrorIs(t, err, ErrInvalidBrowserBinding)
	}
}

func TestBrowserBindingCheckDoesNotSlideButPersistsObservedShorterExpiry(t *testing.T) {
	_, _, sess, spec := browserBindingFixture(t)
	now := time.Now().UTC()
	binding, err := sess.createBrowserBinding(t.Context(), spec, 6*time.Hour, now.Add(-time.Minute))
	require.NoError(t, err)
	checked, err := sess.CheckBrowserBinding(t.Context(), binding.ID, binding.Revision, 6*time.Hour)
	require.NoError(t, err)
	require.Equal(t, binding, checked)
	_, err = sess.CheckBrowserBinding(t.Context(), binding.ID, binding.Revision, time.Second)
	require.ErrorIs(t, err, ErrBrowserBindingDenied)
	_, err = sess.CheckBrowserBinding(t.Context(), binding.ID, binding.Revision, 24*time.Hour)
	require.ErrorIs(t, err, ErrBrowserBindingDenied)
	_, err = sess.UseBrowserBinding(t.Context(), binding.ID, binding.Revision, 24*time.Hour)
	require.ErrorIs(t, err, ErrBrowserBindingDenied)
	entries, err := sess.BrowserBindings(t.Context())
	require.NoError(t, err)
	require.Equal(t, binding.LastUsedAt, entries[0].LastUsedAt)
	require.Equal(t, binding.Revision, entries[0].Revision)
	require.Equal(t, binding.LastUsedAt.Add(time.Second), entries[0].ExpiresAt)
}
