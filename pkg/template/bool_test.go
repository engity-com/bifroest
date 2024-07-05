package template

import (
	"errors"
	"fmt"
	"testing"
)

func TestBool(t *testing.T) {
	cases := []struct {
		plain             string
		data              any
		expected          bool
		expectedNewErr    error
		expectedRenderErr error
	}{{
		data:     map[string]any{"foo": "bar"},
		plain:    "{{.foo}}",
		expected: true,
	}, {
		data:     map[string]any{"foo": "true"},
		plain:    "{{.foo}}",
		expected: true,
	}, {
		data:     map[string]any{"foo": "faLse"},
		plain:    "{{.foo}}",
		expected: false,
	}, {
		data:     map[string]any{"foo": "oFf"},
		plain:    "{{.foo}}",
		expected: false,
	}, {
		data:     map[string]any{"foo": "off"},
		plain:    "{{.foo}}",
		expected: false,
	}, {
		data:     map[string]any{"foo": "No"},
		plain:    "{{.foo}}",
		expected: false,
	}, {
		data:              map[string]any{"foobar": "true"},
		plain:             "{{.foo}}",
		expectedRenderErr: errors.New(`template: bool:1:2: executing "bool" at <.foo>: map has no entry for key "foo"`),
	}, {
		data:     map[string]any{"foo": map[string]any{"bar": "abc"}},
		plain:    "{{.foo}}",
		expected: true,
	}, {
		data:     map[string]any{"foo": map[string]any{"bar": "abc"}},
		plain:    "{{.foo.bar}}",
		expected: true,
	}, {
		data:              map[string]any{"foo": map[string]any{"bar": "abc"}},
		plain:             "{{.foo.bars}}",
		expectedRenderErr: errors.New(`template: bool:1:6: executing "bool" at <.foo.bars>: map has no entry for key "bars"`),
	}, {
		data:     map[string]any{"foo": map[string]any{"bar": "abc"}},
		plain:    "{{get .foo `bars`}}",
		expected: false,
	}, {
		data:     map[string]any{"foo": map[string]any{"bar": nil}},
		plain:    "{{.foo.bar}}",
		expected: false,
	}}
	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			instance, actualErr := NewBool(c.plain)
			if expected := c.expectedNewErr; expected != nil {
				if actualErr != nil {
					if actualErr.Error() != expected.Error() {
						t.Fatalf("expected error: %v; but got: %v", expected, actualErr)
					}
				} else {
					t.Fatalf("expected error %v; but got nothing", expected)
				}
			} else if actualErr != nil {
				t.Fatalf("expected no error; but got: %v", actualErr)
			}

			actual, actualErr := instance.Render(c.data)
			if expected := c.expectedRenderErr; expected != nil {
				if actualErr != nil {
					if actualErr.Error() != expected.Error() {
						t.Fatalf("expected error: %v; but got: %v", expected, actualErr)
					}
				} else {
					t.Fatalf("expected error %v; but got nothing", expected)
				}
			} else if actualErr != nil {
				t.Fatalf("expected no error; but got: %v", actualErr)
			}

			if actual != c.expected {
				t.Fatalf("expected %v; but got: %v", c.expected, actual)
			}
		})
	}
}
