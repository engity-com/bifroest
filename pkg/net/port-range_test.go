package net

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
)

func TestNewPortRange(t *testing.T) {
	cases := []struct {
		in          string
		expected    PortRange
		expectedErr string
	}{{
		in:       "",
		expected: PortRange{},
	}, {
		in:       "8080",
		expected: PortRange{8080, 0},
	}, {
		in:       "8080-9090",
		expected: PortRange{8080, 9090},
	}, {
		in:       "8080-8080",
		expected: PortRange{8080, 0},
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
			actual, actualErr := NewPortRange(c.in)
			if expected := c.expectedErr; expected != "" {
				require.EqualError(t, actualErr, expected)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, c.expected, actual)
			}
		})
	}
}

func TestPortRange_String_and_MarshalText(t *testing.T) {
	cases := []struct {
		in          PortRange
		expectedS   string
		expectedB   string
		expectedErr string
	}{{
		in:        PortRange{8080, 9090},
		expectedS: "8080-9090",
		expectedB: "8080-9090",
	}, {
		in:        PortRange{8080, 0},
		expectedS: "8080",
		expectedB: "8080",
	}, {
		in:          PortRange{0, 9090},
		expectedS:   "0-9090",
		expectedErr: "illegal port-range: 0-9090",
	}, {
		in:          PortRange{9090, 8080},
		expectedS:   "9090-8080",
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

func TestPortRange_IsZero(t *testing.T) {
	cases := []struct {
		in       PortRange
		expected bool
	}{{
		in:       PortRange{8080, 9090},
		expected: false,
	}, {
		in:       PortRange{8080, 0},
		expected: false,
	}, {
		in:       PortRange{0, 9090},
		expected: false,
	}, {
		in:       PortRange{},
		expected: true,
	}}

	for _, c := range cases {
		t.Run(c.in.String(), func(t *testing.T) {
			actual := c.in.IsZero()
			require.Equal(t, c.expected, actual)
		})
	}
}

func TestPortRange_Validate(t *testing.T) {
	cases := []struct {
		in       PortRange
		expected string
	}{{
		in:       PortRange{8080, 9090},
		expected: "",
	}, {
		in:       PortRange{8080, 0},
		expected: "",
	}, {
		in:       PortRange{9090, 8080},
		expected: "illegal port-range: 9090-8080",
	}, {
		in:       PortRange{0, 9090},
		expected: "illegal port-range: 0-9090",
	}, {
		in:       PortRange{},
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

func TestPortRange_Clone(t *testing.T) {
	cases := []struct {
		in PortRange
	}{{
		in: PortRange{9090, 8080},
	}}

	for _, c := range cases {
		t.Run(c.in.String(), func(t *testing.T) {
			actual := c.in.Clone()
			require.Equal(t, c.in, actual)
		})
	}
}

func TestPortRange_IsEqualTo(t *testing.T) {
	cases := []struct {
		left     PortRange
		right    PortRange
		expected bool
	}{{
		left:     PortRange{8080, 9090},
		right:    PortRange{8080, 9090},
		expected: true,
	}, {
		left:     PortRange{8080, 9090},
		right:    PortRange{8088, 9090},
		expected: false,
	}, {
		left:     PortRange{8080, 9090},
		right:    PortRange{8080, 9099},
		expected: false,
	}, {
		left:     PortRange{},
		right:    PortRange{},
		expected: true,
	}}

	for _, c := range cases {
		t.Run(c.left.String()+"="+c.right.String(), func(t *testing.T) {
			actual := c.left.IsEqualTo(c.right)
			require.Equal(t, c.expected, actual)
		})
	}
}

func TestPortRange_Test(t *testing.T) {
	cases := []struct {
		instance PortRange
		port     uint16
		expected bool
	}{{
		instance: MustNewPortRange("8080-9090"),
		port:     8080,
		expected: true,
	}, {
		instance: MustNewPortRange("8080-9090"),
		port:     8081,
		expected: true,
	}, {
		instance: MustNewPortRange("8080-9090"),
		port:     9090,
		expected: true,
	}, {
		instance: MustNewPortRange("8080-9090"),
		port:     8079,
		expected: false,
	}, {
		instance: MustNewPortRange("8080-9090"),
		port:     9091,
		expected: false,
	}, {
		instance: MustNewPortRange("8080"),
		port:     8080,
		expected: true,
	}, {
		instance: MustNewPortRange("8080"),
		port:     8079,
		expected: false,
	}, {
		instance: MustNewPortRange("8080"),
		port:     8081,
		expected: false,
	}, {
		instance: MustNewPortRange(""),
		port:     8080,
		expected: false,
	}, {
		instance: MustNewPortRange(""),
		port:     0,
		expected: false,
	}}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%v-%d", c.instance, c.port), func(t *testing.T) {
			actual := c.instance.Test(c.port)
			require.Equal(t, c.expected, actual)
		})
	}
}

func TestPortRange_Iterate(t *testing.T) {
	cases := []struct {
		instance    PortRange
		expected    []uint16
		expectedErr string
	}{{
		instance: MustNewPortRange("10"),
		expected: []uint16{10},
	}, {
		instance: MustNewPortRange("10-20"),
		expected: []uint16{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}, {
		instance: MustNewPortRange(""),
		expected: nil,
	}, {
		instance:    PortRange{20, 10},
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
