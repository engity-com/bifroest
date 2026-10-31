package password

import (
	"testing"

	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/apr1_crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"github.com/GehirnInc/crypt/sha256_crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/stretchr/testify/require"
)

func TestUnixCryptAdaptersKeepPasswordAndStoredVerifierSeparate(t *testing.T) {
	for _, test := range []struct {
		name string
		new  func() crypt.Crypter
		impl Crypt
		salt string
	}{
		{"md5", md5_crypt.New, &Md5{}, "$1$fixture$"},
		{"apr1", apr1_crypt.New, &Apr1{}, "$apr1$fixture$"},
		{"sha256", sha256_crypt.New, &Sha256{}, "$5$fixture$"},
		{"sha512", sha512_crypt.New, &Sha512{}, "$6$fixture$"},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := test.new().Generate([]byte("correct"), []byte(test.salt))
			require.NoError(t, err)
			require.NoError(t, test.new().Verify(verifier, []byte("correct")))
			for _, input := range []struct {
				name, password string
				valid          bool
			}{{"correct", "correct", true}, {"wrong", "wrong", false}, {"verifier replay", verifier, false}} {
				t.Run(input.name, func(t *testing.T) {
					valid, err := test.impl.Validate(input.password, []byte(verifier))
					require.NoError(t, err)
					require.Equal(t, input.valid, valid)
				})
			}
			t.Run("hash of verifier is not a password", func(t *testing.T) {
				// Knowing the stored verifier must not let a caller manufacture a
				// new verifier and submit that string as a primary password.
				forged, err := test.new().Generate([]byte(verifier), []byte(test.salt))
				require.NoError(t, err)
				valid, err := test.impl.Validate(forged, []byte(verifier))
				require.NoError(t, err)
				require.False(t, valid)
			})
		})
	}
}
