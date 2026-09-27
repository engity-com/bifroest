//go:build unix

package user

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserToCredentials(t *testing.T) {
	tests := map[string]struct {
		groups Groups
		want   []uint32
	}{
		"supplementary groups": {
			groups: Groups{{Gid: 1002}, {Gid: 1003}},
			want:   []uint32{1002, 1003},
		},
		"primary group excluded": {
			groups: Groups{{Gid: 1002}, {Gid: 1001}, {Gid: 1003}},
			want:   []uint32{1002, 1003},
		},
		"no supplementary groups": {
			groups: nil,
			want:   []uint32{},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			credentials := (User{
				Uid:    1000,
				Group:  Group{Gid: 1001},
				Groups: test.groups,
			}).ToCredentials()

			require.Equal(t, uint32(1000), credentials.Uid)
			require.Equal(t, uint32(1001), credentials.Gid)
			require.NotNil(t, credentials.Groups)
			require.Equal(t, test.want, credentials.Groups)
			require.False(t, credentials.NoSetGroups)
		})
	}
}
