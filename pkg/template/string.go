package template

import (
	"fmt"
	"strings"
	"text/template"
)

func NewString(plain string) (String, error) {
	var buf String
	if err := buf.Set(plain); err != nil {
		return String{}, nil
	}
	return buf, nil
}

func MustNewString(plain string) String {
	buf, err := NewString(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type String struct {
	plain string
	tmpl  *template.Template
}

func (this String) Render(data any) (string, error) {
	if tmpl := this.tmpl; tmpl != nil {
		var buf strings.Builder
		if err := tmpl.Execute(&buf, data); err != nil {
			return "", err
		}
		return strings.TrimSpace(buf.String()), nil
	}
	return "", nil
}

func (this String) String() string {
	return this.plain
}

func (this String) IsZero() bool {
	return len(this.plain) == 0
}

func (this String) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this *String) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*this = String{}
		return nil
	}
	tmpl, err := NewTemplate("string", string(text))
	if err != nil {
		return fmt.Errorf("illegal string template: %w", err)
	}
	*this = String{
		plain: string(text),
		tmpl:  tmpl,
	}
	return nil
}

func (this *String) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this String) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case String:
		return this.isEqualTo(&v)
	case *String:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this String) isEqualTo(other *String) bool {
	return this.plain == other.plain
}
