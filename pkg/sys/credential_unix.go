//go:build unix

package sys

import (
	goerrors "errors"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func EnrichCredentials(credentials *syscall.Credential, plainUser, plainGroup string) error {
	credentials.Groups = []uint32{}
	if plainUser == "" && plainGroup == "" {
		return nil
	}
	if plainUser == "" {
		credentials.Uid = uint32(os.Geteuid())
	}

	var u *user.User
	var err error
	if plainUser != "" {
		if uid, numericErr := strconv.ParseUint(plainUser, 10, 32); numericErr == nil {
			credentials.Uid = uint32(uid)
			u, err = user.LookupId(plainUser)
			var unknownUserIdError user.UnknownUserIdError
			if goerrors.As(err, &unknownUserIdError) {
				u = nil
				err = nil
			}
		} else {
			u, err = user.Lookup(plainUser)
		}
		if err != nil {
			return err
		}
		if u != nil {
			uid, err := strconv.ParseUint(u.Uid, 10, 32)
			if err != nil {
				return err
			}
			credentials.Uid = uint32(uid)
		}
	}

	if plainGroup != "" {
		if gid, numericErr := strconv.ParseUint(plainGroup, 10, 32); numericErr == nil {
			credentials.Gid = uint32(gid)
		} else {
			g, err := user.LookupGroup(plainGroup)
			if err != nil {
				return err
			}
			gid, err := strconv.ParseUint(g.Gid, 10, 32)
			if err != nil {
				return err
			}
			credentials.Gid = uint32(gid)
		}
	} else if u != nil {
		gid, err := strconv.ParseUint(u.Gid, 10, 32)
		if err != nil {
			return err
		}
		credentials.Gid = uint32(gid)
	} else {
		credentials.Gid = credentials.Uid
	}

	if u != nil {
		groupIds, err := u.GroupIds()
		if err != nil {
			return err
		}
		credentials.Groups = make([]uint32, len(groupIds))
		for i, groupId := range groupIds {
			value, err := strconv.ParseUint(groupId, 10, 32)
			if err != nil {
				return err
			}
			credentials.Groups[i] = uint32(value)
		}
	}
	return nil
}
