package template

import (
	"encoding"
	"fmt"
	"strings"
	"unicode"
)

type EnforceableValue[V any] interface {
	Render(data any) (V, error)
	String() string
	IsZero() bool
	encoding.TextMarshaler
	Validate() error
	IsEqualTo(any) bool
}

type EnforceableValueP[T EnforceableValue[V], V any] interface {
	*T
	Set(string) error
	encoding.TextUnmarshaler
}

func NewEnforceable[T EnforceableValue[V], V any, PT EnforceableValueP[T, V]](plain string) (Enforceable[T, V, PT], error) {
	var result Enforceable[T, V, PT]
	if err := result.Set(plain); err != nil {
		return Enforceable[T, V, PT]{}, err
	}
	return result, nil
}

func MustNewEnforceable[T EnforceableValue[V], V any, PT EnforceableValueP[T, V]](plain string) Enforceable[T, V, PT] {
	result, err := NewEnforceable[T, V, PT](plain)
	if err != nil {
		panic(err)
	}
	return result
}

// Enforceable adds an optional ! marker to a templated value. T retains its
// ordinary conversion rules; only the wrapper interprets enforcement.
type Enforceable[T EnforceableValue[V], V any, PT EnforceableValueP[T, V]] struct {
	value    T
	source   String
	enforced bool
}

func (this Enforceable[T, V, PT]) Render(data any) (rendered V, enforced bool, err error) {
	return this.RenderBounded(data, 0)
}

// RenderBounded limits the rendered value's UTF-8 bytes, excluding the marker.
// Zero leaves the text unbounded. Bounds belong to the consuming property.
func (this Enforceable[T, V, PT]) RenderBounded(data any, maximumBytes int) (rendered V, enforced bool, err error) {
	if this.IsZero() {
		return rendered, false, nil
	}
	plain, err := this.source.Render(data)
	if err != nil {
		return rendered, false, err
	}
	enforced = this.enforced
	marked := strings.TrimLeftFunc(plain, unicode.IsSpace)
	if !enforced && strings.HasPrefix(marked, "!") {
		enforced, plain = true, marked[1:]
	}
	if maximumBytes > 0 && len(plain) > maximumBytes {
		return rendered, false, fmt.Errorf("enforceable value exceeds %d bytes", maximumBytes)
	}
	value, err := this.value.Render(plain)
	if err != nil {
		return rendered, false, err
	}
	return value, enforced, nil
}

func (this Enforceable[T, V, PT]) IsHardCoded() bool {
	return this.source.IsHardCoded()
}

func (this Enforceable[T, V, PT]) String() string {
	v := this.source.String()
	if this.enforced {
		return "!" + v
	}
	return v
}

func (this Enforceable[T, V, PT]) IsZero() bool {
	return !this.enforced && this.source.IsZero()
}

func (this Enforceable[T, V, PT]) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this *Enforceable[T, V, PT]) UnmarshalText(text []byte) error {
	plain := string(text)
	enforced := strings.HasPrefix(plain, "!")
	if enforced {
		plain = plain[1:]
	}
	source, err := NewString(plain)
	if err != nil {
		return err
	}
	var value T
	var valueP PT = &value
	// A fixed passthrough feeds already-rendered text into T's existing parser.
	// Never parse the rendered text as another template: a value containing
	// {{...}} must remain data, not become a second executable template.
	if err := valueP.Set("{{.}}"); err != nil {
		return err
	}
	*this = Enforceable[T, V, PT]{value: value, source: source, enforced: enforced}
	return nil
}

func (this *Enforceable[T, V, PT]) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this Enforceable[T, V, PT]) Validate() error {
	if this.IsHardCoded() {
		if _, _, err := this.Render(nil); err != nil {
			return err
		}
	}
	return this.value.Validate()
}

func (this Enforceable[T, V, PT]) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Enforceable[T, V, PT]:
		return this.isEqualTo(&v)
	case *Enforceable[T, V, PT]:
		return v != nil && this.isEqualTo(v)
	default:
		return false
	}
}

func (this Enforceable[T, V, PT]) isEqualTo(other *Enforceable[T, V, PT]) bool {
	return this.enforced == other.enforced && this.source.IsEqualTo(other.source)
}
