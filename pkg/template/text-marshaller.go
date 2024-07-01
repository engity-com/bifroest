package template

import (
	"encoding"
	"fmt"
	"github.com/engity-com/bifroest/internal/text/template"
	"strings"
)

func NewTextMarshaller[T TextMarshallerArgument, PT TextMarshallerArgumentP[T]](plain string) (TextMarshaller[T, PT], error) {
	var buf TextMarshaller[T, PT]
	if err := buf.Set(plain); err != nil {
		return TextMarshaller[T, PT]{}, nil
	}
	return buf, nil
}

func MustNewTextMarshaller[T TextMarshallerArgument, PT TextMarshallerArgumentP[T]](plain string) TextMarshaller[T, PT] {
	buf, err := NewTextMarshaller[T, PT](plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type TextMarshallerArgument interface {
	encoding.TextMarshaler
}

type TextMarshallerArgumentP[T TextMarshallerArgument] interface {
	*T
	encoding.TextUnmarshaler
}

type TextMarshaller[T TextMarshallerArgument, PT TextMarshallerArgumentP[T]] struct {
	plain string
	tmpl  *template.Template
}

func (this TextMarshaller[T, PT]) Render(data any) (T, error) {
	var bufT T

	if tmpl := this.tmpl; tmpl != nil {
		var buf strings.Builder
		if err := tmpl.Execute(&buf, data); err != nil {
			return bufT, err
		}
		plain := buf.String()

		var bufTP PT = new(T)
		if err := bufTP.UnmarshalText([]byte(plain)); err != nil {
			return bufT, fmt.Errorf("templated value results in a value that cannot be parsed: %q - %w", buf.String(), err)
		}
		bufT = *bufTP
	}

	return bufT, nil
}

func (this TextMarshaller[T, PT]) String() string {
	return this.plain
}

func (this TextMarshaller[T, PT]) IsZero() bool {
	return len(this.plain) == 0
}

func (this TextMarshaller[T, PT]) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this *TextMarshaller[T, PT]) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*this = TextMarshaller[T, PT]{}
		return nil
	}
	tmpl, err := NewTemplate("textMarshaller", string(text))
	if err != nil {
		return fmt.Errorf("illegal textMarshaller template: %w", err)
	}
	*this = TextMarshaller[T, PT]{
		plain: string(text),
		tmpl:  tmpl,
	}
	return nil
}

func (this *TextMarshaller[T, PT]) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this TextMarshaller[T, PT]) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case TextMarshaller[T, PT]:
		return this.isEqualTo(&v)
	case *TextMarshaller[T, PT]:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this TextMarshaller[T, PT]) isEqualTo(other *TextMarshaller[T, PT]) bool {
	return this.plain == other.plain
}
