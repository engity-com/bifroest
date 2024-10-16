package template

import (
	"fmt"
	"strings"

	"github.com/engity-com/bifroest/internal/text/template"
)

func NewBool(plain string) (Bool, error) {
	var buf Bool
	if err := buf.Set(plain); err != nil {
		return Bool{}, err
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

func BoolOf(plain bool) Bool {
	result := Bool{
		isHardCoded:    true,
		hardCodedValue: plain,
	}
	if plain {
		result.plain = "true"
	} else {
		result.plain = "false"
	}
	return result
}

type Bool struct {
	isHardCoded    bool
	hardCodedValue bool
	plain          string
	tmpl           *template.Template
}

func (this Bool) Render(data any) (bool, error) {
	if this.isHardCoded {
		return this.hardCodedValue, nil
	}

	if tmpl := this.tmpl; tmpl != nil {
		var buf strings.Builder
		if err := tmpl.Execute(&buf, data); err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(buf.String())) {
		case "false", "disabled", "0", "no", "off", "", "<nil>", "nil", "null":
			return false, nil
		default:
			return true, nil
		}
	}
	return false, nil
}

func (this Bool) IsHardCoded() bool {
	return this.isHardCoded
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
		*this = Bool{
			isHardCoded:    true,
			hardCodedValue: false,
		}
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(string(text))) {
	case "false", "disabled", "0", "no", "off", "", "<nil>", "nil", "null":
		*this = Bool{
			isHardCoded:    true,
			hardCodedValue: false,
			plain:          string(text),
		}
		return nil
	case "true", "enabled", "1", "yes", "on":
		*this = Bool{
			isHardCoded:    true,
			hardCodedValue: true,
			plain:          string(text),
		}
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

func (this Bool) Validate() error {
	return nil
}

func (this Bool) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Bool:
		return this.isEqualTo(&v)
	case *Bool:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Bool) isEqualTo(other *Bool) bool {
	return this.plain == other.plain
}
