package sys

import (
	"errors"
	"os"
)

func IsNotExist(err error) bool {
	var pe *os.PathError
	return errors.As(err, &pe) && os.IsNotExist(pe)
}
