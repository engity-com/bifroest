package template

import (
	"fmt"
	"testing"
)

func TestString(t *testing.T) {
	cases := []struct {
		plain             string
		data              any
		expected          string
		expectedNewErr    error
		expectedRenderErr error
	}{{
		data:     map[string]any{"foo": "bar"},
		plain:    "{{.foo}}",
		expected: "bar",
	}, {
		data:     map[string]any{"foo": ""},
		plain:    "{{.foo}}",
		expected: "",
	}, {
		data:     map[string]any{"foo": nil},
		plain:    "{{or .foo ``}}",
		expected: "",
	}, {
		data:     map[string]any{"foo": map[string]any{"bar": "abc"}},
		plain:    "{{.foo.bar}}",
		expected: "abc",
	}, {
		data:     map[string]any{"foo": map[string]any{"bar": nil}},
		plain:    "{{or .foo.bar ``}}",
		expected: "",
	}}
	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			instance, actualErr := NewString(c.plain)
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

			if actual != c.expected {
				t.Fatalf("expected %v; but got: %v", c.expected, actual)
			}
		})
	}
}
