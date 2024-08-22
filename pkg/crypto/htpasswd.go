package crypto

import (
	"bytes"
	"github.com/tg123/go-htpasswd"
)

type Htpasswd struct {
	file  *htpasswd.File
	plain string
}

func (this Htpasswd) Match(username, password string) bool {
	if v := this.file; v != nil {
		return v.Match(username, password)
	}
	return false
}

func (this Htpasswd) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this Htpasswd) String() string {
	return this.plain
}

func (this *Htpasswd) UnmarshalText(text []byte) error {
	text = bytes.TrimSpace(text)
	if len(text) == 0 {
		*this = Htpasswd{}
		return nil
	}

	f, err := htpasswd.NewFromReader(bytes.NewBuffer(text), htpasswd.DefaultSystems, nil)
	if err != nil {
		return err
	}
	*this = Htpasswd{f, string(text)}
	return nil
}

func (this *Htpasswd) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this Htpasswd) Validate() error {
	return nil
}

func (this Htpasswd) IsZero() bool {
	return this.file == nil
}

func (this Htpasswd) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Htpasswd:
		return this.isEqualTo(&v)
	case *Htpasswd:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Htpasswd) isEqualTo(other *Htpasswd) bool {
	return this.plain == other.plain
}
