package crypto

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestPublicKeysGet(t *testing.T) {
	key1 := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ed255191Pub)))
	key2 := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ed255192Pub)))
	actual, err := PublicKeys("# CAs\r\n" + key1 + " first\r\n\t" + key2 + "\tsecond\r\n").Get()
	require.NoError(t, err)
	require.Len(t, actual, 2)
	require.Equal(t, ed255191Pub.Marshal(), actual[0].Marshal())
	require.Equal(t, ed255192Pub.Marshal(), actual[1].Marshal())
}

func TestPublicKeysRejectsIllegalEntries(t *testing.T) {
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ed255191Pub)))
	for name, value := range map[string]string{
		"authorized-key-option": "restrict " + key,
		"invalid-key":           "ssh-ed25519 invalid",
		"invalid-second-key":    key + "\nssh-ed25519 invalid",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := PublicKeys(value).Get()
			require.ErrorIs(t, err, ErrIllegalPublicKeysFormat)
			require.Error(t, PublicKeys(value).Validate())
		})
	}
}

func TestPublicKeysValidation(t *testing.T) {
	require.NoError(t, PublicKeys("").Validate())
	require.Error(t, PublicKeys("# no key").Validate())
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ed255191Pub)))
	require.NoError(t, PublicKeys(key+" comment").Validate())
}

func TestPublicKeysForEachCanStop(t *testing.T) {
	value := PublicKeys(fmt.Sprintf("%s\n%s", ssh.MarshalAuthorizedKey(ed255191Pub), ssh.MarshalAuthorizedKey(ed255192Pub)))
	count := 0
	require.NoError(t, value.ForEach(func(_ int, _ ssh.PublicKey, _ string) (bool, error) {
		count++
		return false, nil
	}))
	require.Equal(t, 1, count)
}
