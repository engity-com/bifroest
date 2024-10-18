package crypto

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	ErrIllegalPasswordFile = errors.Config.Newf("illegal password file")
)

type PasswordFile string

func (this PasswordFile) String() string {
	return string(this)
}

func (this PasswordFile) MarshalText() ([]byte, error) {
	return []byte(strings.Clone(this.String())), nil
}

func (this *PasswordFile) Set(plain string) error {
	buf := PasswordFile(plain)
	if err := buf.Validate(); err != nil {
		return err
	}
	*this = buf
	return nil
}

func (this PasswordFile) GetPassword() (Password, error) {
	if len(this) == 0 {
		return Password{}, nil
	}
	f, err := os.Open(string(this))
	if sys.IsNotExist(err) {
		return Password{}, nil
	}
	if err != nil {
		return Password{}, fmt.Errorf("%w: %v", ErrIllegalPasswordFile, err)
	}
	defer common.IgnoreCloseError(f)

	b, err := io.ReadAll(f)
	if err != nil {
		return Password{}, fmt.Errorf("%w: %v", ErrIllegalPasswordFile, err)
	}

	result := Password(b)
	if err := result.Validate(); err != nil {
		return Password{}, fmt.Errorf("%w: %v", ErrIllegalPasswordFile, err)
	}

	return result, nil
}

func (this PasswordFile) SetPassword(v Password) error {
	if this.IsZero() {
		if !v.IsZero() {
			return errors.System.Newf("cannot save password, because this file reference is empty")
		}
		return nil
	}

	b, err := v.MarshalText()
	if err != nil {
		return errors.System.Newf("cannot save password to %s: %w", this, err)
	}
	_ = os.MkdirAll(filepath.Dir(string(this)), 0700)
	if err := os.WriteFile(string(this), b, 0600); err != nil {
		return errors.System.Newf("cannot save password to %s: %w", this, err)
	}
	return nil
}

func (this *PasswordFile) UnmarshalText(b []byte) error {
	return this.Set(string(b))
}

func (this PasswordFile) Validate() error {
	_, err := this.GetPassword()
	return err
}

func (this PasswordFile) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case PasswordFile:
		return this.isEqualTo(&v)
	case *PasswordFile:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this PasswordFile) IsZero() bool {
	return len(this) == 0
}

func (this PasswordFile) isEqualTo(other *PasswordFile) bool {
	return string(this) == string(*other)
}
