//go:build unix

package protocol

import (
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/engity-com/bifroest/pkg/errors"
)

func authorizeReverseTCPPort(port uint16, targetUser string, configured bool) error {
	return authorizeReverseTCPPortForUID(port, targetUser, configured, os.Geteuid())
}

func authorizeReverseTCPPortForUID(port uint16, targetUser string, configured bool, effectiveUID int) error {
	if port == 0 || port >= 1024 {
		return nil
	}
	denied := errors.Permission.Newf("reverse TCP port %d requires a configured target user with UID 0", port)
	if !configured || targetUser == "" || effectiveUID != 0 {
		return denied
	}
	name, _, _ := strings.Cut(targetUser, ":")
	if name == "" {
		return denied
	}
	if uid, err := strconv.ParseUint(name, 10, 32); err == nil {
		if uid == 0 {
			return nil
		}
		return denied
	}
	resolved, err := user.Lookup(name)
	if err != nil || resolved.Uid != "0" {
		return denied
	}
	return nil
}
