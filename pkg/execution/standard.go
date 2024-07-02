package execution

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"slices"
)

type Standard struct {
	UsingSudo bool
}

func (this Standard) Execute(program string, args ...string) error {
	var c *exec.Cmd
	if this.UsingSudo {
		c = exec.Command("sudo", slices.Concat([]string{program}, args)...)
	} else {
		c = exec.Command(program, args...)
	}
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return &Error{
				ExitCode: ee.ExitCode(),
				Stderr:   stderr.Bytes(),
			}
		} else {
			return fmt.Errorf("%v failed: %v; stderr: %s", c, err, stderr.Bytes())
		}
	}
	return nil
}
