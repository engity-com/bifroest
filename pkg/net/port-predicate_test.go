package net

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
)

func TestNewPortPredicate(t *testing.T) {
	cases := []struct {
		in          string
		expected    PortPredicate
		expectedErr string
	}{{
		in:       "",
		expected: PortPredicate{},
	}, {
		in:       "8080",
		expected: PortPredicate{MustNewPortRanges("8080"), MustNewPortRanges("")},
	}, {
		in:       "8080-9090",
		expected: PortPredicate{MustNewPortRanges("8080-9090"), MustNewPortRanges("")},
	}, {
		in:       "!8080",
		expected: PortPredicate{MustNewPortRanges(""), MustNewPortRanges("8080")},
	}, {
		in:       "!8080-9090",
		expected: PortPredicate{MustNewPortRanges(""), MustNewPortRanges("8080-9090")},
	}, {
		in:       "100-199,200,!300-399,400-499,!500-599",
		expected: PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("300-399,500-599")},
	}, {
		in:          "9090-8080",
		expectedErr: "illegal port-range: 9090-8080",
	}, {
		in:          "abc-def",
		expectedErr: "illegal port-range: abc-def",
	}, {
		in:          "8080-9090-666",
		expectedErr: "illegal port-range: 8080-9090-666",
	}}

	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			actual, actualErr := NewPortPredicate(c.in)
			if expected := c.expectedErr; expected != "" {
				require.EqualError(t, actualErr, expected)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, c.expected, actual)
			}
		})
	}
}

func TestPortPredicate_String_and_MarshalText(t *testing.T) {
	cases := []struct {
		in          PortPredicate
		expectedS   string
		expectedB   string
		expectedErr string
	}{{
		in:        PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("300-399,500-599")},
		expectedS: "100-199,200,400-499,!300-399,!500-599",
		expectedB: "100-199,200,400-499,!300-399,!500-599",
	}, {
		in:        PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("")},
		expectedS: "100-199,200,400-499",
		expectedB: "100-199,200,400-499",
	}, {
		in:        PortPredicate{MustNewPortRanges(""), MustNewPortRanges("300-399,500-599")},
		expectedS: "!300-399,!500-599",
		expectedB: "!300-399,!500-599",
	}, {
		in:        PortPredicate{},
		expectedS: "",
		expectedB: "",
	}, {
		in:          PortPredicate{PortRanges{PortRange{9090, 8080}}, nil},
		expectedS:   "9090-8080",
		expectedErr: "illegal port-range: 9090-8080",
	}, {
		in:          PortPredicate{nil, PortRanges{PortRange{9090, 8080}}},
		expectedS:   "!9090-8080",
		expectedErr: "illegal port-range: 9090-8080",
	}}

	for i, c := range cases {
		t.Run(fmt.Sprintf("c%d", i), func(t *testing.T) {
			{
				actual := c.in.String()
				require.Equal(t, c.expectedS, actual)
			}
			{
				actual, actualErr := c.in.MarshalText()
				if expected := c.expectedErr; expected != "" {
					require.EqualError(t, actualErr, expected)
				} else {
					require.NoError(t, actualErr)
					require.Equal(t, []byte(c.expectedB), actual)
				}
			}
		})
	}
}

func TestPortPredicate_IsZero(t *testing.T) {
	cases := []struct {
		in       PortPredicate
		expected bool
	}{{
		in:       PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("300-399,500-599")},
		expected: false,
	}, {
		in:       PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("")},
		expected: false,
	}, {
		in:       PortPredicate{MustNewPortRanges(""), MustNewPortRanges("300-399,500-599")},
		expected: false,
	}, {
		in:       PortPredicate{},
		expected: true,
	}}

	for _, c := range cases {
		t.Run(c.in.String(), func(t *testing.T) {
			actual := c.in.IsZero()
			require.Equal(t, c.expected, actual)
		})
	}
}

func TestPortPredicate_Validate(t *testing.T) {
	cases := []struct {
		in       PortPredicate
		expected string
	}{{
		in:       PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("300-399,500-599")},
		expected: "",
	}, {
		in:       PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("")},
		expected: "",
	}, {
		in:       PortPredicate{MustNewPortRanges(""), MustNewPortRanges("300-399,500-599")},
		expected: "",
	}, {
		in:       PortPredicate{PortRanges{PortRange{9090, 8080}}, nil},
		expected: "illegal port-range: 9090-8080",
	}, {
		in:       PortPredicate{nil, PortRanges{PortRange{9090, 8080}}},
		expected: "illegal port-range: 9090-8080",
	}, {
		in:       PortPredicate{},
		expected: "",
	}}

	for _, c := range cases {
		t.Run(c.in.String(), func(t *testing.T) {
			actual := c.in.Validate()
			if expected := c.expected; expected != "" {
				require.EqualError(t, actual, expected)
			} else {
				require.NoError(t, actual)
			}
		})
	}
}

func TestPortPredicate_Clone(t *testing.T) {
	cases := []struct {
		in PortPredicate
	}{{
		in: PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("300-399,500-599")},
	}}

	for _, c := range cases {
		t.Run(c.in.String(), func(t *testing.T) {
			actual := c.in.Clone()
			require.Equal(t, c.in, actual)
		})
	}
}

func TestPortPredicate_IsEqualTo(t *testing.T) {
	cases := []struct {
		left     PortPredicate
		right    PortPredicate
		expected bool
	}{{
		left:     PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("300-399,500-599")},
		right:    PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("300-399,500-599")},
		expected: true,
	}, {
		left:     PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("300-399,500-599")},
		right:    PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("")},
		expected: false,
	}, {
		left:     PortPredicate{MustNewPortRanges("100-199,200,400-499"), MustNewPortRanges("300-399,500-599")},
		right:    PortPredicate{MustNewPortRanges(""), MustNewPortRanges("300-399,500-599")},
		expected: false,
	}, {
		left:     PortPredicate{},
		right:    PortPredicate{},
		expected: true,
	}}

	for _, c := range cases {
		t.Run(c.left.String()+"="+c.right.String(), func(t *testing.T) {
			actual := c.left.IsEqualTo(c.right)
			require.Equal(t, c.expected, actual)
		})
	}
}

func TestPortPredicate_Test(t *testing.T) {
	cases := []struct {
		instance PortPredicate
		port     uint16
		expected bool
	}{{
		instance: MustNewPortPredicate("8080-9090"),
		port:     8080,
		expected: true,
	}, {
		instance: MustNewPortPredicate("8080-9090"),
		port:     8081,
		expected: true,
	}, {
		instance: MustNewPortPredicate("8080-9090"),
		port:     9090,
		expected: true,
	}, {
		instance: MustNewPortPredicate("8080-9090"),
		port:     8079,
		expected: false,
	}, {
		instance: MustNewPortPredicate("8080-9090"),
		port:     9091,
		expected: false,
	}, {
		instance: MustNewPortPredicate("10-20,!12-18"),
		port:     10,
		expected: true,
	}, {
		instance: MustNewPortPredicate("10-20,!12-18"),
		port:     20,
		expected: true,
	}, {
		instance: MustNewPortPredicate("10-20,!12-18"),
		port:     12,
		expected: false,
	}, {
		instance: MustNewPortPredicate("10-20,!12-18"),
		port:     18,
		expected: false,
	}, {
		instance: MustNewPortPredicate("8080"),
		port:     8080,
		expected: true,
	}, {
		instance: MustNewPortPredicate("8080"),
		port:     8079,
		expected: false,
	}, {
		instance: MustNewPortPredicate("8080"),
		port:     8081,
		expected: false,
	}, {
		instance: MustNewPortPredicate(""),
		port:     8080,
		expected: true,
	}, {
		instance: MustNewPortPredicate(""),
		port:     0,
		expected: false,
	}}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%v/%d", c.instance, c.port), func(t *testing.T) {
			actual := c.instance.Test(c.port)
			require.Equal(t, c.expected, actual)
		})
	}
}

func TestPortPredicate_Iterate(t *testing.T) {
	cases := []struct {
		instance    PortPredicate
		expected    []uint16
		expectedErr string
	}{{
		instance: MustNewPortPredicate("10"),
		expected: []uint16{10},
	}, {
		instance: MustNewPortPredicate("10-20"),
		expected: []uint16{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}, {
		instance: MustNewPortPredicate("10-20,!12-18"),
		expected: []uint16{10, 11, 19, 20},
	}, {
		instance: MustNewPortPredicate(""),
		expected: allUint16Values(),
	}, {
		instance:    PortPredicate{PortRanges{PortRange{20, 10}}, nil},
		expectedErr: "illegal port-range: 20-10",
	}, {
		instance:    PortPredicate{nil, PortRanges{PortRange{20, 10}}},
		expectedErr: "illegal port-range: 20-10",
	}}

	for _, c := range cases {
		t.Run(c.instance.String(), func(t *testing.T) {
			actual, actualErr := common.CollectOrFail(c.instance.Iterate())
			if expected := c.expectedErr; expected != "" {
				require.EqualError(t, actualErr, expected)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, c.expected, actual)
			}
		})
	}
}

func allUint16Values() []uint16 {
	result := make([]uint16, 65535)
	for v := uint16(0); v < 65535; v++ {
		result[v] = v + 1
	}
	return result
}
