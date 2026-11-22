//go:build unix

package user

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrInvalidAccountFacts     = errors.Config.Newf("invalid account facts")
	ErrAccountFieldUnavailable = errors.Config.Newf("account field was not supplied")
)

// AccountFacts describes an assumed existing Unix account. A UID pointer is
// required so a missing UID cannot be mistaken for an explicitly supplied 0.
// Nil metadata pointers mean unknown facts, not empty values or host defaults.
// A primary group is independent of the ordered supplementary group list.
type AccountFacts struct {
	Name        string
	Uid         *Id
	DisplayName *string
	Group       *Group
	Groups      *Groups
	Shell       *string
	HomeDir     *string
}

// Snapshot is an immutable, metadata-only view using User's production field
// mapping and ID types. It holds no repository, native credentials or account
// management capability. It is not authentication evidence or a Lua/report API.
type Snapshot struct {
	account User
	known   map[string]bool
}

func NewSnapshot(facts AccountFacts) (*Snapshot, error) {
	if !validSnapshotIdentity(facts.Name) || facts.Uid == nil {
		return nil, ErrInvalidAccountFacts
	}
	result := &Snapshot{account: User{Name: facts.Name, Uid: *facts.Uid}, known: map[string]bool{"name": true, "uid": true, "managed": true}}
	for _, field := range []struct {
		name   string
		source *string
		target *string
	}{
		{"displayName", facts.DisplayName, &result.account.DisplayName},
		{"homeDir", facts.HomeDir, &result.account.HomeDir},
		{"shell", facts.Shell, &result.account.Shell},
	} {
		if field.source != nil {
			*field.target = *field.source
			result.known[field.name] = true
		}
	}
	if facts.Group != nil {
		if !validSnapshotIdentity(facts.Group.Name) {
			return nil, ErrInvalidAccountFacts
		}
		result.account.Group = *facts.Group
		result.known["group"], result.known["gid"] = true, true
	}
	if facts.Groups != nil {
		names, ids := map[string]bool{}, map[GroupId]bool{}
		for _, group := range *facts.Groups {
			if !validSnapshotIdentity(group.Name) || names[group.Name] || ids[group.Gid] {
				return nil, ErrInvalidAccountFacts
			}
			names[group.Name], ids[group.Gid] = true, true
		}
		result.account.Groups = slices.Clone(*facts.Groups)
		result.known["groups"], result.known["gids"] = true, true
	}
	return result, nil
}

func (this *Snapshot) Identity() (string, Id) {
	if this == nil {
		return "", 0
	}
	return this.account.Name, this.account.Uid
}

func (this *Snapshot) GetField(name string) (any, bool, error) {
	if this == nil || this.known == nil {
		return nil, false, ErrInvalidAccountFacts
	}
	if !this.known[name] {
		// Missing and newly added fields must fail before invoking any getter.
		switch name {
		case "displayName", "group", "gid", "groups", "gids", "shell", "homeDir":
			return nil, false, errors.Config.Newf("%w: %s", ErrAccountFieldUnavailable, name)
		default:
			return nil, false, errors.Config.Newf("unknown field %q", name)
		}
	}
	value, present, err := this.account.GetField(name)
	if groups, ok := value.(Groups); ok {
		value = slices.Clone(groups)
	}
	return value, present, err
}

func validSnapshotIdentity(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}
