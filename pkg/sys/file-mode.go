package sys

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

type FileMode fs.FileMode

func (this FileMode) String() string {
	result := strconv.FormatUint(uint64(this), 8)
	ml := 4 - len(result)
	if ml > 0 {
		result = strings.Repeat("0", ml)
	}
	return result
}

func (this FileMode) MarshalText() ([]byte, error) {
	return []byte(this.String()), nil
}

func (this *FileMode) UnmarshalText(in []byte) error {
	buf, err := strconv.ParseUint(string(in), 8, 32)
	if err != nil {
		return fmt.Errorf("invalid file mode: %s", in)
	}
	*this = FileMode(buf)
	return nil
}

func (this *FileMode) Set(in string) error {
	return this.UnmarshalText([]byte(in))
}
