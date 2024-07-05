package template

import (
	"fmt"
	"strings"
	"text/template"
)

func NewBool(plain string) (Bool, error) {
	var buf Bool
	if err := buf.Set(plain); err != nil {
		return Bool{}, nil
	}
	return buf, nil
}

func MustNewBool(plain string) Bool {
	buf, err := NewBool(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type Bool struct {
	plain string
	tmpl  *template.Template
}

func (this Bool) Render(data any) (bool, error) {
	if tmpl := this.tmpl; tmpl != nil {
		var buf strings.Builder
		if err := tmpl.Execute(&buf, data); err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(buf.String())) {
		case "false", "0", "no", "off", "<no value>", "":
			return false, nil
		default:
			return true, nil
		}
	}
	return false, nil
}

func (this Bool) String() string {
	return this.plain
}

func (this Bool) IsZero() bool {
	return len(this.plain) == 0
}

func (this Bool) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this *Bool) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*this = Bool{}
		return nil
	}
	tmpl, err := NewTemplate("bool", string(text))
	if err != nil {
		return fmt.Errorf("illegal bool template: %w", err)
	}
	*this = Bool{
		plain: string(text),
		tmpl:  tmpl,
	}
	return nil
}

func (this *Bool) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}
