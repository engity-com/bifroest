package template

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDuration(t *testing.T) {
	cases := []struct {
		plain             string
		data              any
		expected          time.Duration
		expectedNewErr    error
		expectedRenderErr error
		isHardCoded       bool
		hardCodedValue    time.Duration
	}{{
		data:     map[string]any{"foo": "666s"},
		plain:    "{{.foo}}",
		expected: time.Second * 666,
	}, {
		data:              map[string]any{"foo": "-11"},
		plain:             "{{.foo}}",
		expectedRenderErr: errors.New(`templated duration results in a value that cannot be parsed as duration: "-11"`),
	}, {
		data:              map[string]any{"foobar": "666"},
		plain:             "{{.foo}}",
		expectedRenderErr: errors.New(`template: duration:1:2: executing "duration" at <.foo>: map has no entry for key "foo"`),
	}, {
		data:              map[string]any{"foo": map[string]any{"bar": "abc"}},
		plain:             "{{.foo.bars}}",
		expectedRenderErr: errors.New(`template: duration:1:6: executing "duration" at <.foo.bars>: map has no entry for key "bars"`),
	}, {
		data:     map[string]any{"foo": map[string]any{"bar": "666"}},
		plain:    "{{get .foo `bars`}}",
		expected: 0,
	}, {
		data:     map[string]any{"foo": map[string]any{"bar": nil}},
		plain:    "{{.foo.bar}}",
		expected: 0,
	}, {
		plain:          "666m",
		expected:       666 * time.Minute,
		isHardCoded:    true,
		hardCodedValue: 666 * time.Minute,
	}, {
		plain:          "",
		expected:       0,
		isHardCoded:    true,
		hardCodedValue: 0,
	}, {
		plain:          "-666m",
		expected:       -666 * time.Minute,
		isHardCoded:    true,
		hardCodedValue: -666 * time.Minute,
	}}
	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			instance, actualErr := NewDuration(c.plain)
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

			assert.Equal(t, c.isHardCoded, instance.isHardCoded)
			assert.Equal(t, c.hardCodedValue, instance.hardCodedValue)

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
