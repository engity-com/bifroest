package template

import (
	"errors"
	"fmt"
	"testing"
)

func TestUint64(t *testing.T) {
	cases := []struct {
		plain             string
		data              any
		expected          uint64
		expectedNewErr    error
		expectedRenderErr error
	}{{
		data:     map[string]any{"foo": "666"},
		plain:    "{{.foo}}",
		expected: 666,
	}, {
		data:              map[string]any{"foo": "-11"},
		plain:             "{{.foo}}",
		expectedRenderErr: errors.New(`templated uint64 results in a value that cannot be parsed as uint64: "-11"`),
	}, {
		data:              map[string]any{"foobar": "666"},
		plain:             "{{.foo}}",
		expectedRenderErr: errors.New(`template: uint64:1:2: executing "uint64" at <.foo>: map has no entry for key "foo"`),
	}, {
		data:              map[string]any{"foo": map[string]any{"bar": "abc"}},
		plain:             "{{.foo.bars}}",
		expectedRenderErr: errors.New(`template: uint64:1:6: executing "uint64" at <.foo.bars>: map has no entry for key "bars"`),
	}, {
		data:     map[string]any{"foo": map[string]any{"bar": "666"}},
		plain:    "{{get .foo `bars`}}",
		expected: 0,
	}, {
		data:     map[string]any{"foo": map[string]any{"bar": nil}},
		plain:    "{{.foo.bar}}",
		expected: 0,
	}}
	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			instance, actualErr := NewUint64(c.plain)
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
