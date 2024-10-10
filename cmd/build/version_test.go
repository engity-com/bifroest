package main

import (
	"iter"
	"slices"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersion_evaluateLatest(t *testing.T) {
	var instance version

	require.NoError(t, instance.Set("v2.3.4"))

	cases := []struct {
		input []string

		expectedMajor bool
		expectedMinor bool
		expectedPatch bool
	}{{
		input:         a[string](),
		expectedMajor: true,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4"),
		expectedMajor: true,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "1.2.3"),
		expectedMajor: true,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "1.2.3", "2.3.3"),
		expectedMajor: true,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "1.2.3", "3.0.0"),
		expectedMajor: false,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "1.2.3", "3.0.0", "2.3.3"),
		expectedMajor: false,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "1.2.3", "3.1.0", "2.3.3"),
		expectedMajor: false,
		expectedMinor: true,
		expectedPatch: true,
	}, {
		input:         a[string]("2.3.4", "1.2.3", "2.3.5"),
		expectedMajor: false,
		expectedMinor: false,
		expectedPatch: false,
	}, {
		input:         a[string]("2.3.4", "1.2.3", "2.4.0"),
		expectedMajor: false,
		expectedMinor: false,
		expectedPatch: true,
	}}

	for _, c := range cases {
		t.Run(strings.Join(c.input, ","), func(t *testing.T) {
			given := instance.cleanClone()

			actualErr := given.evaluateLatest(allSemver(c.input...))
			require.NoError(t, actualErr)
			assert.Equal(t, c.expectedMajor, given.latestMajor)
			assert.Equal(t, c.expectedMinor, given.latestMinor)
			assert.Equal(t, c.expectedPatch, given.latestPatch)
		})
	}
}

func TestVersion_tags_semver(t *testing.T) {
	var instance version

	require.NoError(t, instance.Set("v2.3.4"))

	cases := []struct {
		major bool
		minor bool
		patch bool
		root  string

		outputs []string
	}{{
		major:   false,
		minor:   false,
		patch:   false,
		root:    "ll",
		outputs: a("x2.3.4"),
	}, {
		major:   false,
		minor:   false,
		patch:   true,
		root:    "ll",
		outputs: a("x2.3.4", "x2.3"),
	}, {
		major:   false,
		minor:   true,
		patch:   true,
		root:    "ll",
		outputs: a("x2.3.4", "x2.3", "x2"),
	}, {
		major:   true,
		minor:   true,
		patch:   true,
		root:    "ll",
		outputs: a("x2.3.4", "x2.3", "x2", "ll"),
	}, {
		major:   true,
		minor:   true,
		patch:   false,
		root:    "ll",
		outputs: a("x2.3.4"),
	}, {
		major:   true,
		minor:   false,
		patch:   true,
		root:    "ll",
		outputs: a("x2.3.4", "x2.3"),
	}}

	for _, c := range cases {
		t.Run(strings.Join(c.outputs, ","), func(t *testing.T) {
			given := instance.cleanClone()
			given.latestMajor = c.major
			given.latestMinor = c.minor
			given.latestPatch = c.patch

			actual := slices.Collect(given.tags("x", c.root))
			assert.Equal(t, c.outputs, actual)
		})
	}
}

func TestVersion_tags_other(t *testing.T) {
	cases := []struct {
		input   string
		prefix  string
		root    string
		outputs []string
	}{{
		input:   "x123x",
		prefix:  "p",
		root:    "r",
		outputs: a("px123x"),
	}, {
		input:   "v1.2.3",
		prefix:  "p",
		root:    "r",
		outputs: a("p1.2.3"),
	}}

	for _, c := range cases {
		t.Run(c.input+"-"+c.prefix+"-"+c.root, func(t *testing.T) {
			var instance version
			require.NoError(t, instance.Set(c.input))

			actual := slices.Collect(instance.tags(c.prefix, c.root))
			assert.Equal(t, c.outputs, actual)
		})
	}
}

func a[T any](in ...T) []T {
	return in
}

func allSemver(in ...string) iter.Seq2[*semver.Version, error] {
	return func(yield func(*semver.Version, error) bool) {
		for _, plain := range in {
			if !yield(semver.MustParse(plain), nil) {
				return
			}
		}
	}
}

func (this version) cleanClone() version {
	return version{
		this.semver,
		this.raw,
		false,
		false,
		false,
	}
}
