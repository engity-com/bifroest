package net

import (
	"fmt"
	gonet "net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHostPort(t *testing.T) {
	cases := []struct {
		in          string
		expected    HostPort
		expectedErr string
	}{{
		in:       "127.0.0.1:8080",
		expected: HostPort{MustNewHost("127.0.0.1"), 8080},
	}, {
		in:       "foo:8080",
		expected: HostPort{MustNewHost("foo"), 8080},
	}, {
		in:       "[::1]:8080",
		expected: HostPort{MustNewHost("::1"), 8080},
	}, {
		in:          "127.0.0::8080",
		expectedErr: `illegal host-port: 127.0.0::8080`,
	}, {
		in:          "127.0.0.1:8o80",
		expectedErr: `illegal host-port: invalid port 8o80`,
	}, {
		in:          "127.0.0.1:0",
		expectedErr: `illegal host-port: invalid port 0`,
	}, {
		in:          "[::1:8080",
		expectedErr: `illegal host-port: [::1:8080`,
	}, {
		in:          "::1:8080",
		expectedErr: `illegal host-port: ::1:8080`,
	}, {
		in:          "foo",
		expectedErr: `illegal host-port: foo`,
	}, {
		in:       "",
		expected: HostPort{},
	}}

	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			actual, actualErr := NewHostPort(c.in)
			if expected := c.expectedErr; expected != "" {
				require.EqualError(t, actualErr, expected)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, c.expected, actual)
			}
		})
	}
}

func TestHostPort_String_and_MarshalText(t *testing.T) {
	cases := []struct {
		in          HostPort
		expectedS   string
		expectedB   string
		expectedErr string
	}{{
		in:        HostPort{Host{IP: gonet.IPv4(127, 0, 0, 1)}, 8080},
		expectedS: "127.0.0.1:8080",
		expectedB: "127.0.0.1:8080",
	}, {
		in:        HostPort{Host{IP: gonet.IPv6loopback}, 8080},
		expectedS: "[::1]:8080",
		expectedB: "[::1]:8080",
	}, {
		in:          HostPort{Host{IP: []byte{1, 2, 3}}, 8080},
		expectedS:   "?010203:8080",
		expectedErr: "illegal host-port: illegal IP address: ?010203",
	}, {
		in:        HostPort{Host{Dns: "foo"}, 8080},
		expectedS: "foo:8080",
		expectedB: "foo:8080",
	}, {
		in:        HostPort{},
		expectedS: "",
		expectedB: "",
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

func TestHostPort_IsZero(t *testing.T) {
	cases := []struct {
		in       HostPort
		expected bool
	}{{
		in:       HostPort{MustNewHost("127.0.0.1"), 8080},
		expected: false,
	}, {
		in:       HostPort{Host: MustNewHost("127.0.0.1")},
		expected: false,
	}, {
		in:       HostPort{Port: 8080},
		expected: false,
	}, {
		in:       HostPort{},
		expected: true,
	}}

	for _, c := range cases {
		t.Run(c.in.String(), func(t *testing.T) {
			actual := c.in.IsZero()
			require.Equal(t, c.expected, actual)
		})
	}
}

func TestHostPort_Validate(t *testing.T) {
	cases := []struct {
		in       HostPort
		expected string
	}{{
		in:       HostPort{MustNewHost("127.0.0.1"), 8080},
		expected: "",
	}, {
		in:       HostPort{Host: MustNewHost("127.0.0.1")},
		expected: "illegal host-port: 127.0.0.1:0",
	}, {
		in:       HostPort{Port: 8080},
		expected: "illegal host-port: :8080",
	}, {
		in:       HostPort{},
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

func TestHostPort_Clone(t *testing.T) {
	cases := []struct {
		in HostPort
	}{{
		in: HostPort{MustNewHost("127.0.0.1"), 8080},
	}}

	for _, c := range cases {
		t.Run(c.in.String(), func(t *testing.T) {
			actual := c.in.Clone()
			require.Equal(t, c.in, actual)
		})
	}
}

func TestHostPort_IsEqualTo(t *testing.T) {
	cases := []struct {
		left     HostPort
		right    HostPort
		expected bool
	}{{
		left:     HostPort{MustNewHost("127.0.0.1"), 8080},
		right:    HostPort{MustNewHost("127.0.0.1"), 8080},
		expected: true,
	}, {
		left:     HostPort{MustNewHost("127.0.0.1"), 8080},
		right:    HostPort{MustNewHost("127.0.0."), 8080},
		expected: false,
	}, {
		left:     HostPort{MustNewHost("127.0.0.1"), 8080},
		right:    HostPort{MustNewHost("127.0.0.1"), 808},
		expected: false,
	}, {
		left:     HostPort{},
		right:    HostPort{},
		expected: true,
	}}

	for _, c := range cases {
		t.Run(c.left.String()+"="+c.right.String(), func(t *testing.T) {
			actual := c.left.IsEqualTo(c.right)
			require.Equal(t, c.expected, actual)
		})
	}
}
