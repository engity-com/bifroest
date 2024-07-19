package template

import (
	"fmt"
	"strconv"
	"strings"
	"text/template"
)

func NewUint32(plain string) (Uint32, error) {
	var buf Uint32
	if err := buf.Set(plain); err != nil {
		return Uint32{}, nil
	}
	return buf, nil
}

func MustNewUint32(plain string) Uint32 {
	buf, err := NewUint32(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type Uint32 struct {
	plain string
	tmpl  *template.Template
}

func (this Uint32) Render(data any) (uint32, error) {
	if tmpl := this.tmpl; tmpl != nil {
		var buf strings.Builder
		if err := tmpl.Execute(&buf, data); err != nil {
			return 0, err
		}
		plain := strings.TrimSpace(buf.String())
		if len(plain) == 0 || plain == "<no value>" {
			return 0, nil
		}

		result, err := strconv.ParseUint(plain, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("templated uint32 results in a value that cannot be parsed as uint32: %q", buf.String())
		}
		return uint32(result), nil
	}
	return 0, nil
}

func (this Uint32) String() string {
	return this.plain
}

func (this Uint32) IsZero() bool {
	return len(this.plain) == 0
}

func (this Uint32) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this *Uint32) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*this = Uint32{}
		return nil
	}
	tmpl, err := NewTemplate("uint32", string(text))
	if err != nil {
		return fmt.Errorf("illegal uint32 template: %w", err)
	}
	*this = Uint32{
		plain: string(text),
		tmpl:  tmpl,
	}
	return nil
}

func (this *Uint32) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this Uint32) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Uint32:
		return this.isEqualTo(&v)
	case *Uint32:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Uint32) isEqualTo(other *Uint32) bool {
	return this.plain == other.plain
}
