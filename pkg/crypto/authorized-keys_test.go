package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
)

//nolint:unused
//goland:noinspection ALL
var (
	dsa1Pub, dsa1Fn             = mustSshPublicKey("dsa-1")
	ecdsa1Pub, ecdsa1Fn         = mustSshPublicKey("ecdsa-1")
	ecdsaSk1Pub, ecdsaSk1Fn     = mustSshPublicKey("ecdsa-sk-1")
	ed255191Pub, ed255191Fn     = mustSshPublicKey("ed25519-1")
	ed255192Pub, ed255192Fn     = mustSshPublicKey("ed25519-2")
	ed255193Pub, ed255193Fn     = mustSshPublicKey("ed25519-3")
	ed255194Pub, ed255194Fn     = mustSshPublicKey("ed25519-4")
	ed25519Sk1Pub, ed25519Sk1Fn = mustSshPublicKey("ed25519-sk-1")
	rsa1Pub, rsa1Fn             = mustSshPublicKey("rsa-1")
)

func TestAuthorizedKeys_Get(t *testing.T) {
	of := func(args ...any) AuthorizedKeys {
		strArgs := make([]string, len(args))
		for i, plainArg := range args {
			switch arg := plainArg.(type) {
			case ssh.PublicKey:
				strArgs[i] = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(arg)))
			case int32:
				strArgs[i] = string([]byte{byte(arg)})
			case []byte:
				strArgs[i] = string(arg)
			case string:
				strArgs[i] = arg
			case AuthorizedKeyOption:
				strArgs[i] = arg.String()
			case AuthorizedKeyOptionType:
				strArgs[i] = arg.String()
			default:
				panic(fmt.Errorf("unknown arg type: %T", plainArg))
			}
		}
		return AuthorizedKeys(strings.Join(strArgs, ""))
	}

	cases := []struct {
		given       AuthorizedKeys
		expected    []AuthorizedKeyWithOptions
		expectedErr string
	}{{
		given:    of(ed255191Pub),
		expected: []AuthorizedKeyWithOptions{{ed255191Pub, nil}},
	}, {
		given:    of(ed255191Pub, '\n', ed255192Pub),
		expected: []AuthorizedKeyWithOptions{{ed255191Pub, nil}, {ed255192Pub, nil}},
	}, {
		given:       of("\n foo bar"),
		expectedErr: ErrIllegalAuthorizedKeysFormat.Error(),
	}, {
		given:       of(ed255191Pub, "\n foo bar"),
		expected:    []AuthorizedKeyWithOptions{{ed255191Pub, nil}},
		expectedErr: ErrIllegalAuthorizedKeysFormat.Error(),
	}, {
		given:    of(ed255191Pub, "\n# foo bar"),
		expected: []AuthorizedKeyWithOptions{{ed255191Pub, nil}},
	}, {
		given:    of(""),
		expected: nil,
	}, {
		given:    of("#only a comment"),
		expected: nil,
	}, {
		given:    of(AuthorizedKeyOption{AuthorizedKeyAgentForwarding, ""}, " ", ed255191Pub),
		expected: []AuthorizedKeyWithOptions{{ed255191Pub, []AuthorizedKeyOption{{AuthorizedKeyAgentForwarding, ""}}}},
	}, {
		given:    of(AuthorizedKeyOption{AuthorizedKeyCommand, "abc def"}, " ", ed255191Pub),
		expected: []AuthorizedKeyWithOptions{{ed255191Pub, []AuthorizedKeyOption{{AuthorizedKeyCommand, "abc def"}}}},
	}, {
		given:       of(AuthorizedKeyCommand, "=abc ", ed255191Pub),
		expectedErr: ErrIllegalAuthorizedKeysFormat.Error(),
	}, {
		given:       of(AuthorizedKeyCommand, " ", ed255191Pub),
		expectedErr: ErrIllegalAuthorizedKeysFormat.Error(),
	}}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			actual, actualErr := c.given.Get()
			if c.expectedErr != "" {
				assert.ErrorContains(t, actualErr, c.expectedErr)
			} else {
				require.NoError(t, actualErr)
			}
			assert.Equal(t, c.expected, actual)
		})
	}
}

func mustSshPublicKey(name string) (ssh.PublicKey, string) {
	fn := filepath.Join("testdata", name+".pub")
	b, err := os.ReadFile(fn)
	common.Must(err, "public key file %q must exist and be readable", fn)
	result, _, _, _, err := ssh.ParseAuthorizedKey(b)
	common.Must(err, "public key file %q must contain a valid public key", fn)
	common.MustNotNil(result, "public key file %q must contain a valid public key", fn)
	return result, fn
}
