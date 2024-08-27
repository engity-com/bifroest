package crypto

import (
	"github.com/tg123/go-htpasswd"
)

type HtpasswdFile struct {
	file *htpasswd.File
	fn   string
}

func (this HtpasswdFile) Match(username, password string) bool {
	if v := this.file; v != nil {
		return v.Match(username, password)
	}
	return false
}

func (this HtpasswdFile) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this HtpasswdFile) String() string {
	return this.fn
}

func (this *HtpasswdFile) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*this = HtpasswdFile{}
		return nil
	}

	f, err := htpasswd.New(string(text), htpasswd.DefaultSystems, nil)
	if err != nil {
		return err
	}
	*this = HtpasswdFile{f, string(text)}
	return nil
}

func (this *HtpasswdFile) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this HtpasswdFile) Validate() error {
	return nil
}

func (this HtpasswdFile) IsZero() bool {
	return this.file == nil
}

func (this HtpasswdFile) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case HtpasswdFile:
		return this.isEqualTo(&v)
	case *HtpasswdFile:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this HtpasswdFile) isEqualTo(other *HtpasswdFile) bool {
	return this.fn == other.fn
}
