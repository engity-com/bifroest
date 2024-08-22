package crypto

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAuthorizedKeysFile_Get(t *testing.T) {
	of := func(arg string) AuthorizedKeysFile {
		return AuthorizedKeysFile(arg)
	}

	cases := []struct {
		given       AuthorizedKeysFile
		expected    []AuthorizedKeyWithOptions
		expectedErr string
	}{{
		given:    of(ed255191Fn),
		expected: []AuthorizedKeyWithOptions{{ed255191Pub, nil}},
	}, {
		given:       of("not-existing"),
		expectedErr: "open not-existing",
	}, {
		given: of(""),
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
