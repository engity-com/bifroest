//go:build unix

package user

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
)

func TestRequirementStringsUseIdentityValues(t *testing.T) {
	for _, test := range []struct {
		name string
		uid  *Id
		gid  *GroupId
		want string
	}{
		{want: "<empty>"},
		{name: "account", want: "account"},
		{uid: common.P(Id(1001)), gid: common.P(GroupId(1001)), want: "1001"},
		{name: "account", uid: common.P(Id(1001)), gid: common.P(GroupId(1001)), want: "1001(account)"},
		{name: "root", uid: common.P(Id(0)), gid: common.P(GroupId(0)), want: "0(root)"},
		{name: "maximum", uid: common.P(Id(4294967295)), gid: common.P(GroupId(4294967295)), want: "4294967295(maximum)"},
	} {
		t.Run(test.want, func(t *testing.T) {
			t.Run("user", func(t *testing.T) {
				require.Equal(t, test.want, (Requirement{Name: test.name, Uid: test.uid}).String())
			})
			t.Run("group", func(t *testing.T) {
				require.Equal(t, test.want, (GroupRequirement{Name: test.name, Gid: test.gid}).String())
			})
		})
	}
}
