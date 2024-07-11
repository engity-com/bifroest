package configuration

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

type unmarshalYamlTestCase[T equaler] struct {
	name          string
	yaml          string
	expected      T
	expectedError string
}

func runUnmarshalYamlTests[T equaler](t *testing.T, cases ...unmarshalYamlTestCase[T]) {
	for i, c := range cases {
		name := c.name
		if name == "" {
			name = fmt.Sprintf("case-%d", i)
		}
		t.Run(name, func(t *testing.T) {
			var actual T
			decoder := yaml.NewDecoder(strings.NewReader(c.yaml))
			decoder.KnownFields(true)
			actualErr := decoder.Decode(&actual)
			if expected := c.expectedError; expected == "" {
				assert.NoError(t, actualErr)

				assert.True(t, c.expected.IsEqualTo(actual))
			} else {
				assert.ErrorContains(t, actualErr, expected)
			}
		})
	}
}
