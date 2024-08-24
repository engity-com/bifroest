package template

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/engity-com/bifroest/internal/text/template"
)

func NewUint64(plain string) (Uint64, error) {
	var buf Uint64
	if err := buf.Set(plain); err != nil {
		return Uint64{}, nil
	}
	return buf, nil
}

func Uint64Of(v uint64) Uint64 {
	return Uint64{
		isHardCoded:    true,
		hardCodedValue: v,
		plain:          strconv.FormatUint(v, 10),
	}
}

func MustNewUint64(plain string) Uint64 {
	buf, err := NewUint64(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type Uint64 struct {
	isHardCoded    bool
	hardCodedValue uint64
	plain          string
	tmpl           *template.Template
}

func (this Uint64) Render(data any) (uint64, error) {
	if this.isHardCoded {
		return this.hardCodedValue, nil
	}

	if tmpl := this.tmpl; tmpl != nil {
		var buf strings.Builder
		if err := tmpl.Execute(&buf, data); err != nil {
			return 0, err
		}
		plain := strings.TrimSpace(buf.String())
		if len(plain) == 0 {
			return 0, nil
		}

		result, err := strconv.ParseUint(plain, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("templated uint64 results in a value that cannot be parsed as uint64: %q", buf.String())
		}
		return result, nil
	}
	return 0, nil
}

func (this Uint64) IsHardCoded() bool {
	return this.isHardCoded
}

func (this Uint64) String() string {
	return this.plain
}

func (this Uint64) IsZero() bool {
	return len(this.plain) == 0
}

func (this Uint64) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this *Uint64) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*this = Uint64{
			isHardCoded:    true,
			hardCodedValue: 0,
			plain:          "",
		}
		return nil
	}

	if v, err := strconv.ParseUint(string(text), 10, 64); err == nil {
		*this = Uint64Of(v)
		return nil
	}

	tmpl, err := NewTemplate("uint64", string(text))
	if err != nil {
		return fmt.Errorf("illegal uint64 template: %w", err)
	}
	*this = Uint64{
		plain: string(text),
		tmpl:  tmpl,
	}
	return nil
}

func (this *Uint64) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this Uint64) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Uint64:
		return this.isEqualTo(&v)
	case *Uint64:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Uint64) isEqualTo(other *Uint64) bool {
	return this.plain == other.plain
}
