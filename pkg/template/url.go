package template

import (
	"fmt"
	"net/url"
	"strings"
	"text/template/parse"

	"github.com/engity-com/bifroest/internal/text/template"
)

func NewUrl(plain string) (Url, error) {
	var buf Url
	if err := buf.Set(plain); err != nil {
		return Url{}, nil
	}
	return buf, nil
}

func MustNewUrl(plain string) Url {
	buf, err := NewUrl(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

func UrlOf(in *url.URL) Url {
	if in == nil {
		return Url{}
	}
	return Url{
		hardCoded: in,
		plain:     in.String(),
	}
}

type Url struct {
	plain     string
	hardCoded *url.URL
	tmpl      *template.Template
}

func (this Url) Render(data any) (*url.URL, error) {
	if v := this.hardCoded; v != nil {
		return v, nil
	}

	if tmpl := this.tmpl; tmpl != nil {
		var buf strings.Builder
		if err := tmpl.Execute(&buf, data); err != nil {
			return nil, err
		}
		if buf.Len() == 0 {
			return nil, nil
		}
		return url.Parse(buf.String())
	}

	return nil, nil
}

func (this Url) IsHardCoded() bool {
	return this.hardCoded != nil
}

func (this Url) String() string {
	return this.plain
}

func (this Url) IsZero() bool {
	return len(this.plain) == 0
}

func (this Url) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this *Url) UnmarshalText(text []byte) error {
	tmpl, err := NewTemplate("url", string(text))
	if err != nil {
		return fmt.Errorf("illegal url template: %w", err)
	}
	if len(tmpl.Root.Nodes) == 0 {
		if len(text) == 0 {
			*this = Url{}
			return nil
		}

		parsed, err := url.Parse(string(text))
		if err != nil {
			return fmt.Errorf("illegal url template: %w", err)
		}
		*this = Url{
			hardCoded: parsed,
			plain:     string(text),
		}
		return nil
	}
	if len(tmpl.Root.Nodes) == 1 {
		if tn, ok := tmpl.Root.Nodes[0].(*parse.TextNode); ok {
			if len(tn.Text) == 0 {
				*this = Url{}
				return nil
			}

			parsed, err := url.Parse(string(tn.Text))
			if err != nil {
				return fmt.Errorf("illegal url template: %w", err)
			}
			*this = Url{
				hardCoded: parsed,
				plain:     string(tn.Text),
			}
			return nil
		}
	}

	*this = Url{
		plain: string(text),
		tmpl:  tmpl,
	}
	return nil
}

func (this *Url) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this Url) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Url:
		return this.isEqualTo(&v)
	case *Url:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Url) isEqualTo(other *Url) bool {
	return this.plain == other.plain
}
