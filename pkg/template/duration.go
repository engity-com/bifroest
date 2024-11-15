package template

import (
	"fmt"
	"strings"
	"time"

	"github.com/engity-com/bifroest/internal/text/template"
)

func NewDuration(plain string) (Duration, error) {
	var buf Duration
	if err := buf.Set(plain); err != nil {
		return Duration{}, err
	}
	return buf, nil
}

func DurationOf(v time.Duration) Duration {
	return Duration{
		isHardCoded:    true,
		hardCodedValue: v,
		plain:          v.String(),
	}
}

func MustNewDuration(plain string) Duration {
	buf, err := NewDuration(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type Duration struct {
	isHardCoded    bool
	hardCodedValue time.Duration
	plain          string
	tmpl           *template.Template
}

func (this Duration) Render(data any) (time.Duration, error) {
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

		result, err := time.ParseDuration(plain)
		if err != nil {
			return 0, fmt.Errorf("templated duration results in a value that cannot be parsed as duration: %q", buf.String())
		}
		return result, nil
	}
	return 0, nil
}

func (this Duration) IsHardCoded() bool {
	return this.isHardCoded
}

func (this Duration) String() string {
	return this.plain
}

func (this Duration) IsZero() bool {
	return len(this.plain) == 0
}

func (this Duration) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this *Duration) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*this = Duration{
			isHardCoded:    true,
			hardCodedValue: 0,
			plain:          "",
		}
		return nil
	}

	if v, err := time.ParseDuration(string(text)); err == nil {
		*this = DurationOf(v)
		return nil
	}

	tmpl, err := NewTemplate("duration", string(text))
	if err != nil {
		return fmt.Errorf("illegal duration template: %w", err)
	}
	*this = Duration{
		plain: string(text),
		tmpl:  tmpl,
	}
	return nil
}

func (this *Duration) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this Duration) Validate() error {
	return nil
}

func (this Duration) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Duration:
		return this.isEqualTo(&v)
	case *Duration:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Duration) isEqualTo(other *Duration) bool {
	return this.plain == other.plain
}
