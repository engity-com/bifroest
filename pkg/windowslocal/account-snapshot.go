package windowslocal

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrInvalidAccountFacts     = errors.Config.Newf("invalid account facts")
	ErrAccountFieldUnavailable = errors.Config.Newf("account field was not supplied")
)

// AccountGroupFacts describes one explicitly supplied direct group identity.
// It does not claim that the user belongs to any native/domain/nested group.
type AccountGroupFacts struct {
	Name string
	SID  string
}

// AccountFacts describes an assumed existing account, not an authentication or
// native account-policy result. Name and SID must both be supplied. Nil metadata
// pointers mean unknown facts; non-nil pointers can explicitly contain empty
// values, including an empty group list. No host defaults are inferred.
//
// The fixture layer must validate SID syntax, account scope and consistency of
// the complete scenario. This constructor does not verify native identities.
type AccountFacts struct {
	Identity    Account
	DisplayName *string
	HomeDir     *string
	Shell       *string
	Groups      *[]AccountGroupFacts
}

// AccountSnapshot is an immutable, metadata-only account view. It has no token,
// native lookup, profile, process or credential capability. It deliberately does
// not implement PasswordAccountView: supplied facts cannot stand in for a fresh
// successful native password-account policy check. This is not a Lua/report API.
type AccountSnapshot struct {
	identity                    Account
	displayName, homeDir, shell *string
	groups                      []group
	groupsKnown                 bool
}

func NewAccountSnapshot(facts AccountFacts) (*AccountSnapshot, error) {
	if !validAccountFactIdentity(facts.Identity.Name) || !validAccountFactIdentity(facts.Identity.SID) {
		return nil, ErrInvalidAccountFacts
	}
	result := &AccountSnapshot{identity: facts.Identity}
	result.displayName = copyAccountTextFact(facts.DisplayName)
	result.homeDir = copyAccountTextFact(facts.HomeDir)
	result.shell = copyAccountTextFact(facts.Shell)
	if facts.Groups != nil {
		result.groupsKnown = true
		if *facts.Groups != nil {
			result.groups = make([]group, len(*facts.Groups))
		}
		names, ids := map[string]bool{}, map[string]bool{}
		for i, value := range *facts.Groups {
			name := strings.ToLower(value.Name)
			if !validAccountFactIdentity(value.Name) || !validAccountFactIdentity(value.SID) || names[name] || ids[value.SID] {
				return nil, ErrInvalidAccountFacts
			}
			names[name], ids[value.SID] = true, true
			result.groups[i] = group{Name: value.Name, SID: value.SID}
		}
	}
	return result, nil
}

func (this *AccountSnapshot) Identity() (string, string) {
	if this == nil {
		return "", ""
	}
	return this.identity.Name, this.identity.SID
}

func (this *AccountSnapshot) GetField(name string) (any, bool, error) {
	if this == nil || this.identity.Name == "" || this.identity.SID == "" {
		return nil, false, ErrInvalidAccountFacts
	}
	return accountField(name, this.identity, this.textField, this.groupFields)
}

func (this *AccountSnapshot) textField(name string) (string, error) {
	var value *string
	switch name {
	case "displayName":
		value = this.displayName
	case "homeDir":
		value = this.homeDir
	case "shell":
		value = this.shell
	}
	if value == nil {
		return "", errors.Config.Newf("%w: %s", ErrAccountFieldUnavailable, name)
	}
	return *value, nil
}

func (this *AccountSnapshot) groupFields() ([]group, error) {
	if !this.groupsKnown {
		return nil, errors.Config.Newf("%w: groups", ErrAccountFieldUnavailable)
	}
	return this.groups, nil
}

func copyAccountTextFact(value *string) *string {
	if value == nil {
		return nil
	}
	copyOfValue := *value
	return &copyOfValue
}

func validAccountFactIdentity(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}
