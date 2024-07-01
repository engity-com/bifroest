package template

import (
	"fmt"
	"github.com/engity-com/bifroest/internal/text/template"
	"strings"
	"text/template/parse"
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
	isHardCoded bool
	plain       string
	tmpl        *template.Template
}

func (this String) Render(data any) (string, error) {
	if this.isHardCoded {
		return this.plain, nil
	}

	if tmpl := this.tmpl; tmpl != nil {
		var buf strings.Builder
		if err := tmpl.Execute(&buf, data); err != nil {
			return "", err
		}
		return buf.String(), nil
	}
	return "", nil
}

func (this String) IsHardCoded() bool {
	return this.isHardCoded
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
	tmpl, err := NewTemplate("string", string(text))
	if err != nil {
		return fmt.Errorf("illegal string template: %w", err)
	}
	if len(tmpl.Root.Nodes) == 0 {
		*this = String{
			isHardCoded: true,
			plain:       string(text),
		}
		return nil
	}
	if len(tmpl.Root.Nodes) == 1 {
		if tn, ok := tmpl.Root.Nodes[0].(*parse.TextNode); ok {
			*this = String{
				isHardCoded: true,
				plain:       string(tn.Text),
			}
			return nil
		}
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
