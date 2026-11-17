package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
)

func TestSSHRememberedCredentialSurvivesRestartAndRequiresRegisteredKey(t *testing.T) {
	repository, conf, sess, spec := browserBindingFixture(t)
	conf.FileMode = 0644 // Private binding metadata must not inherit a public file mode.
	public, err := spec.PublicKey.Parse()
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	credential := SSHRememberedCredential{Identity: spec.Identity, Credential: authentication.SessionCredential{Kind: "simple", Method: "password"}}
	before, err := sess.AuthorizationToken(t.Context())
	require.NoError(t, err)
	require.NoError(t, sess.RememberSSHKey(t.Context(), key, credential))
	stored, err := sess.SSHKeyCredential(t.Context(), key)
	require.NoError(t, err)
	require.Equal(t, credential, stored)
	after, err := sess.AuthorizationToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, before, after, "remembering a device must not replace primary authorization")
	require.NoError(t, repository.Close())
	reopened, err := NewFsRepository(t.Context(), conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	restored, err := reopened.FindBy(t.Context(), sess.Flow(), sess.Id(), nil)
	require.NoError(t, err)
	stored, err = restored.(SSHRememberMeSession).SSHKeyCredential(t.Context(), key)
	require.NoError(t, err)
	require.Equal(t, credential, stored)
	require.NoError(t, restored.DeletePublicKey(t.Context(), key))
	_, err = restored.(SSHRememberMeSession).SSHKeyCredential(t.Context(), key)
	require.ErrorIs(t, err, ErrNoSuchSession, "orphaned metadata must never authorize a revoked key")
}

func TestSSHRememberedStateProtectsDamagedSessionsFromAutomaticRemoval(t *testing.T) {
	repository, _, sess, _ := browserBindingFixture(t)
	marker, err := repository.file(sess.Flow(), sess.Id(), FsFileSshRemember)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(marker, []byte("damaged retained binding state"), 0600))
	info, err := repository.file(sess.Flow(), sess.Id(), FsFileSession)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(info, []byte("broken session metadata"), 0600))
	auto := true
	_, err = repository.FindBy(t.Context(), sess.Flow(), sess.Id(), &FindOpts{AutoCleanUpAllowed: &auto})
	require.Error(t, err)
	retained, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Equal(t, "damaged retained binding state", string(retained))
	require.FileExists(t, info)
}

func TestDeletePublicKeyClosesFilesAndPreservesOtherBucketEntries(t *testing.T) {
	repository, _, sess, spec := browserBindingFixture(t)
	public, err := spec.PublicKey.Parse()
	require.NoError(t, err)
	removed, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	other, err := ssh.NewPublicKey(otherPublic)
	require.NoError(t, err)
	require.NoError(t, sess.AddPublicKey(t.Context(), removed))
	path, err := repository.file(sess.Flow(), sess.Id(), repository.publicKeyKind(removed))
	require.NoError(t, err)
	// Model a shared hash bucket without relying on generating a hash collision.
	kept := base64.StdEncoding.EncodeToString(other.Marshal()) + "\n"
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(removed.Marshal())+"\n"+kept), 0600))
	require.NoError(t, sess.DeletePublicKey(t.Context(), removed))
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, kept, string(contents), "only the non-revoked candidate may be written back")
	present, err := sess.HasPublicKey(t.Context(), removed)
	require.NoError(t, err)
	require.False(t, present)
	require.NoError(t, os.Remove(path), "all read/write handles must be closed, including on Windows")
}
