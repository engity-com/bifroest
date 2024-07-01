package user

import (
	"bytes"
	"fmt"
	"os/exec"
)

func execCommand(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	_, err := c.Output()
	if err != nil {
		return fmt.Errorf("cannot run %s: %v -- %s", err, stderr.Bytes())
	}
	return nil
}
