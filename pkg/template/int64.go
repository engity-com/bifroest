package template

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/engity-com/bifroest/internal/text/template"
)

func NewInt64(plain string) (Int64, error) {
	var buf Int64
	if err := buf.Set(plain); err != nil {
		return Int64{}, err
	}
	return buf, nil
}

func Int64Of(v int64) Int64 {
	return Int64{
		isHardCoded:    true,
		hardCodedValue: v,
		plain:          strconv.FormatInt(v, 10),
	}
}

func MustNewInt64(plain string) Int64 {
	buf, err := NewInt64(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type Int64 struct {
	isHardCoded    bool
	hardCodedValue int64
	plain          string
	tmpl           *template.Template
}

func (this Int64) Render(data any) (int64, error) {
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

		result, err := strconv.ParseInt(plain, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("templated int64 results in a value that cannot be parsed as int64: %q", buf.String())
		}
		return result, nil
	}
	return 0, nil
}

func (this Int64) IsHardCoded() bool {
	return this.isHardCoded
}

func (this Int64) String() string {
	return this.plain
}

func (this Int64) IsZero() bool {
	return len(this.plain) == 0
}

func (this Int64) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this *Int64) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*this = Int64{
			isHardCoded:    true,
			hardCodedValue: 0,
			plain:          "",
		}
		return nil
	}

	if v, err := strconv.ParseInt(string(text), 10, 64); err == nil {
		*this = Int64Of(int64(v))
		return nil
	}

	tmpl, err := NewTemplate("int64", string(text))
	if err != nil {
		return fmt.Errorf("illegal int64 template: %w", err)
	}
	*this = Int64{
		plain: string(text),
		tmpl:  tmpl,
	}
	return nil
}

func (this *Int64) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this Int64) Validate() error {
	return nil
}

func (this Int64) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Int64:
		return this.isEqualTo(&v)
	case *Int64:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Int64) isEqualTo(other *Int64) bool {
	return this.plain == other.plain
}
