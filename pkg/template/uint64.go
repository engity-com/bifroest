package template

import (
	"fmt"
	"strconv"
	"strings"
	"text/template"
)

func NewUint64(plain string) (Uint64, error) {
	var buf Uint64
	if err := buf.Set(plain); err != nil {
		return Uint64{}, nil
	}
	return buf, nil
}

func MustNewUint64(plain string) Uint64 {
	buf, err := NewUint64(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type Uint64 struct {
	plain string
	tmpl  *template.Template
}

func (this Uint64) Render(data any) (uint64, error) {
	if tmpl := this.tmpl; tmpl != nil {
		var buf strings.Builder
		if err := tmpl.Execute(&buf, data); err != nil {
			return 0, err
		}
		plain := strings.TrimSpace(buf.String())
		if len(plain) == 0 || plain == "<no value>" {
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
		*this = Uint64{}
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
