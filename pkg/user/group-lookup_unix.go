//go:build unix && !android

package user

import "bytes"

func LookupGroup(name string, allowBadName bool) (*Group, error) {
	if !allowBadName && validateGroupName([]byte(name), false) != nil {
		return nil, nil
	}

	return lookupGroupBy(func(entry *etcGroupEntry) bool {
		return bytes.Equal(entry.name, []byte(name))
	})
}

func LookupGid(gid uint32, allowBadName bool) (*Group, error) {
	return lookupGroupBy(func(entry *etcGroupEntry) bool {
		if entry.gid != gid {
			return false
		}
		if !allowBadName && validateGroupName(entry.name, false) != nil {
			return false
		}
		return true
	})
}

func lookupGroupBy(predicate func(entry *etcGroupEntry) bool) (*Group, error) {
	var result *Group

	if err := decodeEtcGroup(true, func(entry *etcGroupEntry) error {
		if !predicate(entry) {

		}

		u := entry.toGroup()
		result = u
		return codecConsumeEnd
	}); err != nil {
		return nil, err
	}

	return result, nil
}

func (this *etcGroupEntry) toGroup() *Group {
	return &Group{
		Name: string(this.name),
		Gid:  this.gid,
	}
}
