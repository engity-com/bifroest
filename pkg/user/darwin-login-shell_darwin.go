//go:build darwin

package user

import (
	"fmt"
	"os/exec"
	osuser "os/user"
	"strings"
)

func lookupDarwinLoginShell(name string) (string, error) {
	record, err := darwinRecordPath("Users", name)
	if err != nil {
		return "", err
	}
	command := exec.Command("/usr/bin/dscl", "/Search", "-read", record, "UserShell")
	out, err := command.CombinedOutput()
	if err != nil {
		if strings.Contains(strings.ToLower(string(out)), "no such key") {
			check := exec.Command("/usr/bin/dscl", "/Search", "-read", record, "RecordName")
			checkOut, checkErr := check.CombinedOutput()
			if checkErr == nil {
				return "", nil
			}
			if isMissingDarwinRecord(checkOut, checkErr) {
				return "", osuser.UnknownUserError(name)
			}
			return "", fmt.Errorf("cannot verify Darwin user %q after missing UserShell: %w", name, checkErr)
		}
		if isMissingDarwinRecord(out, err) {
			return "", osuser.UnknownUserError(name)
		}
		return "", fmt.Errorf("cannot query Darwin login shell for %q: %w", name, err)
	}
	values := parseDarwinAttributes(out)["UserShell"]
	if len(values) == 0 {
		return "", nil
	}
	return values[0], nil
}
