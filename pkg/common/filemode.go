package common

import (
	"fmt"
	"os"
	"strconv"
)

func NewFileMode(plain string) (FileMode, error) {
	var buf FileMode
	if err := buf.Set(plain); err != nil {
		return FileMode{}, nil
	}
	return buf, nil
}

func MustNewFileMode(plain string) FileMode {
	buf, err := NewFileMode(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type FileMode struct {
	v os.FileMode
}

func (this FileMode) IsZero() bool {
	return this.v == 0
}

func (this FileMode) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this FileMode) String() string {
	if v := this.v; v != 0 {
		return fmt.Sprintf("%04d", v)
	}
	return ""
}

func (this *FileMode) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		this.v = 0
		return nil
	}

	if len(text) != 4 {
		return fmt.Errorf("illegal perm: %q", string(text))
	}

	plain, err := strconv.ParseUint(string(text), 10, 32)
	if err != nil {
		return fmt.Errorf("illegal perm: %q", string(text))
	}

	this.v = os.FileMode(plain)
	return nil
}

func (this *FileMode) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this FileMode) Get() os.FileMode {
	return this.v
}

func (this FileMode) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case FileMode:
		return this.isEqualTo(&v)
	case *FileMode:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this FileMode) isEqualTo(other *FileMode) bool {
	return this.v == other.v
}
