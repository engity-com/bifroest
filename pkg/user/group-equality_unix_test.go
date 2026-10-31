//go:build unix

package user

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGroupsEqualityRequiresEveryMemberAndAcceptsEmptyGroups(t *testing.T) {
	for _, test := range []struct {
		name        string
		left, right Groups
		equal       bool
	}{
		{"empty", nil, nil, true},
		{"same", Groups{{1001, "first"}, {1002, "second"}}, Groups{{1001, "first"}, {1002, "second"}}, true},
		{"changed second", Groups{{1001, "first"}, {1002, "second"}}, Groups{{1001, "first"}, {2002, "other"}}, false},
		{"changed first", Groups{{1001, "first"}, {1002, "second"}}, Groups{{2001, "other"}, {1002, "second"}}, false},
		{"different lengths", Groups{{1001, "first"}}, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.equal, test.left.IsEqualTo(test.right))
			left := &User{Name: "alice", Uid: 1001, Groups: test.left}
			right := &User{Name: "alice", Uid: 1001, Groups: test.right}
			require.Equal(t, test.equal, left.IsEqualTo(right), "account stability includes the complete group list")
		})
	}
}
