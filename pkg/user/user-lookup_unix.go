//go:build moo && unix

package user

import (
	"bytes"
	"fmt"
)

func Lookup(name string, allowBadName, skipIllegalEntries bool) (*User, error) {
	if !allowBadName && validateUserName([]byte(name), false) != nil {
		return nil, nil
	}

	return lookupBy(allowBadName, skipIllegalEntries, func(entry *etcPasswdEntry) bool {
		return bytes.Equal(entry.name, []byte(name))
	})
}

func LookupUid(uid uint32, allowBadName, skipIllegalEntries bool) (*User, error) {
	return lookupBy(allowBadName, skipIllegalEntries, func(entry *etcPasswdEntry) bool {
		if entry.uid != uid {
			return false
		}
		if !allowBadName && validateUserName(entry.name, false) != nil {
			return false
		}
		return true
	})
}

func lookupBy(allowBadName, skipIllegalEntries bool, predicate func(entry *etcPasswdEntry) bool) (*User, error) {
	var result *User

	if err := decodeEtcPasswd(true, func(entry *etcPasswdEntry, lpErr error) (codecConsumerResult, error) {
		if lpErr != nil {
			if skipIllegalEntries {
				return codecConsumerResultContinue, nil
			}
			return 0, lpErr
		}
		if !predicate(entry) {
			return codecConsumerResultContinue, nil
		}

		u, err := entry.toUser(allowBadName, skipIllegalEntries)
		if err != nil {
			return 0, err
		}
		result = u
		return codecConsumerResultCancel, nil
	}); err != nil {
		return nil, err
	}

	return result, nil
}

func (this *etcPasswdEntry) toUser(allowBadName, skipIllegalEntries bool) (*User, error) {
	result := User{
		Name:        string(this.name),
		DisplayName: string(this.geocs),
		Uid:         this.uid,
		Shell:       string(this.shell),
		HomeDir:     string(this.homeDir),
	}

	if v, err := LookupGid(this.gid, allowBadName, skipIllegalEntries); err != nil {
		return nil, fmt.Errorf("lookup of user's %d(%s) group %d failed: %w", this.uid, string(this.name), this.gid, err)
	} else if v == nil {
		return nil, fmt.Errorf("lookup of user's %d(%s) group %d failed: no such group", this.uid, string(this.name), this.gid)
	} else {
		result.Group = *v
	}

	if err := decodeEtcGroup(allowBadName, func(entry *etcGroupEntry, lpErr error) (codecConsumerResult, error) {
		if lpErr != nil {
			if skipIllegalEntries {
				return codecConsumerResultContinue, nil
			}
			return 0, lpErr
		}
		for _, candidate := range entry.userNames {
			if bytes.Equal(candidate, this.name) {
				result.Groups = append(result.Groups, *entry.toGroup())
			}
		}
		return codecConsumerResultContinue, nil
	}); err != nil {
		return nil, fmt.Errorf("lookup of user's %d(%s) groups (/etc/group) failed: %w", this.uid, string(this.name), err)
	}

	return &result, nil
}
