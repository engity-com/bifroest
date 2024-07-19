package user

import (
	"fmt"
	"github.com/engity-com/yasshd/pkg/sys"
	"testing"
)

func TestEnsure(t *testing.T) {
	cases := []struct {
		req []Requirement
		u   User
		err error
	}{{
		req: []Requirement{{
			Name:        "x-foo",
			DisplayName: "X-Foo-name",
			Uid:         1600,
			Group:       GroupRequirement{1600, "x-foo-group"},
			Groups:      nil,
			Shell:       "/bin/foo",
		}},
		u: User{
			Name:        "x-foo",
			DisplayName: "X-Foo-name",
			Uid:         1600,
			Group:       Group{1600, "x-foo-group"},
			Groups:      []Group{{1600, "x-foo-group"}},
			Shell:       "/bin/foo",
			HomeDir:     "/home/x-foo",
		},
	}, {
		req: []Requirement{{
			Uid: 1600,
		}},
		u: User{
			Name:        "user-1600",
			DisplayName: "",
			Uid:         1600,
			Group:       Group{1500, "yasshd"},
			Groups:      []Group{{1500, "yasshd"}},
			Shell:       "/bin/sh",
			HomeDir:     "/home/user-1600",
		},
	}, {
		req: []Requirement{{
			Name: "x-foo",
		}, {
			Name:        "x-foo",
			DisplayName: "X-Foo-name",
			Uid:         1600,
			Group:       GroupRequirement{1600, "x-foo-group"},
			Groups:      nil,
			Shell:       "/bin/foo",
		}},
		u: User{
			Name:        "x-foo",
			DisplayName: "X-Foo-name",
			Uid:         1600,
			Group:       Group{1600, "x-foo-group"},
			Groups:      []Group{{1600, "x-foo-group"}},
			Shell:       "/bin/foo",
			HomeDir:     "/home/x-foo",
		},
	}, {
		req: []Requirement{{
			Name: "x-foo",
		}, {
			Name:        "x-foo",
			DisplayName: "X-Foo-name",
		}, {
			Name:   "x-foo",
			Uid:    1600,
			Group:  GroupRequirement{1600, "x-foo-group"},
			Groups: nil,
			Shell:  "/bin/foo",
		}},
		u: User{
			Name:    "x-foo",
			Uid:     1600,
			Group:   Group{1600, "x-foo-group"},
			Groups:  []Group{{1600, "x-foo-group"}},
			Shell:   "/bin/foo",
			HomeDir: "/home/x-foo",
		},
	}}

	purge := func() {
		purgeOldUsers(t, "x-foo", "user-1600")
		purgeOldGroups(t, "x-foo-group", defaultGroup.Name)
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			purge()
			defer purge()

			var actual *User
			for ensureStep, req := range c.req {
				var err error
				actual, err = DefaultEnsurer.Ensure(&req, nil)
				if err != nil {
					if c.err != nil {
						if c.err.Error() != err.Error() {
							t.Fatalf("[%d] error was expected but different: %v != %v", ensureStep, c.err, err)
						}
					} else {
						t.Fatalf("[%d] unexpected error: %v", ensureStep, err)
					}
				} else if c.err != nil {
					t.Fatalf("[%d] error %v was expected, but missing", ensureStep, c.err)
				}
			}

			if actual == nil || !actual.IsEqualTo(&c.u) {
				t.Fatal("actual and expected are different")
			}
		})
	}
}

func purgeOldUsers(t *testing.T, names ...string) {
	for _, name := range names {
		if err := Delete(name, nil, sys.DefaultExecutor); err != nil {
			t.Fatalf("cannot purge old user %s: %v", name, err)
		}
	}
}

func purgeOldGroups(t *testing.T, names ...string) {
	for _, name := range names {
		if err := DeleteGroup(name, nil, sys.DefaultExecutor); err != nil {
			t.Fatalf("cannot purge old group %s: %v", name, err)
		}
	}
}
