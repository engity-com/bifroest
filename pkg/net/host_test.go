package net

import (
	"fmt"
	gonet "net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHost(t *testing.T) {
	cases := []struct {
		in          string
		expected    Host
		expectedErr string
	}{{
		in:       "127.0.0.1",
		expected: Host{IP: gonet.IPv4(127, 0, 0, 1)},
	}, {
		in:       "foo",
		expected: Host{Dns: "foo"},
	}, {
		in:       "::1",
		expected: Host{IP: gonet.IPv6loopback},
	}, {
		in:       "",
		expected: Host{},
	}}

	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			actual, actualErr := NewHost(c.in)
			if expected := c.expectedErr; expected != "" {
				require.EqualError(t, actualErr, expected)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, c.expected, actual)
			}
		})
	}
}

func TestHost_SetNetAddr(t *testing.T) {
	cases := []struct {
		in          gonet.Addr
		expected    Host
		expectedErr string
	}{{
		in:       &gonet.IPNet{IP: gonet.IPv4(1, 2, 3, 4)},
		expected: Host{IP: gonet.IPv4(1, 2, 3, 4)},
	}, {
		in:          &gonet.IPNet{},
		expectedErr: "invalid address with empty IP",
	}, {
		in:       &gonet.IPAddr{IP: gonet.IPv4(1, 2, 3, 4)},
		expected: Host{IP: gonet.IPv4(1, 2, 3, 4)},
	}, {
		in:          &gonet.IPAddr{},
		expectedErr: "invalid address with empty IP",
	}, {
		in:       &gonet.TCPAddr{IP: gonet.IPv4(1, 2, 3, 4)},
		expected: Host{IP: gonet.IPv4(1, 2, 3, 4)},
	}, {
		in:          &gonet.TCPAddr{},
		expectedErr: "invalid address with empty IP",
	}, {
		in:       &gonet.UDPAddr{IP: gonet.IPv4(1, 2, 3, 4)},
		expected: Host{IP: gonet.IPv4(1, 2, 3, 4)},
	}, {
		in:          &gonet.UDPAddr{},
		expectedErr: "invalid address with empty IP",
	}, {
		in: &gonet.UnixAddr{
			Name: "foo",
			Net:  "bar",
		},
		expectedErr: "invalid address type: foo",
	}, {
		in:          nil,
		expectedErr: "invalid address type: <nil>",
	}}

	for _, c := range cases {
		t.Run(fmt.Sprint(c.in), func(t *testing.T) {
			var instance Host
			actualErr := instance.SetNetAddr(c.in)
			if expected := c.expectedErr; expected != "" {
				require.EqualError(t, actualErr, expected)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, c.expected, instance)
			}
		})
	}
}

func TestHost_WithPort(t *testing.T) {
	cases := []struct {
		host        Host
		port        uint16
		expected    HostPort
		expectedErr string
	}{{
		host:     MustNewHost("127.0.0.1"),
		port:     8080,
		expected: HostPort{MustNewHost("127.0.0.1"), 8080},
	}, {
		host:     MustNewHost("foo"),
		port:     8080,
		expected: HostPort{MustNewHost("foo"), 8080},
	}, {
		host:        MustNewHost("foo"),
		port:        0,
		expectedErr: "illegal host-port: foo:0",
	}}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%v:%d", c.host, c.port), func(t *testing.T) {
			actual, actualErr := c.host.WithPort(c.port)
			if expected := c.expectedErr; expected != "" {
				require.EqualError(t, actualErr, expected)
			} else {
				require.NoError(t, actualErr)
				require.Equal(t, c.expected, actual)
			}
		})
	}
}

func TestHost_String_and_MarshalText(t *testing.T) {
	cases := []struct {
		in          Host
		expectedS   string
		expectedB   string
		expectedErr string
	}{{
		in:        Host{IP: gonet.IPv4(127, 0, 0, 1)},
		expectedS: "127.0.0.1",
		expectedB: "127.0.0.1",
	}, {
		in:        Host{IP: gonet.IPv6loopback},
		expectedS: "::1",
		expectedB: "::1",
	}, {
		in:          Host{IP: []byte{1, 2, 3}},
		expectedS:   "?010203",
		expectedErr: "address 010203: invalid IP address",
	}, {
		in:        Host{Dns: "foo"},
		expectedS: "foo",
		expectedB: "foo",
	}, {
		in:        Host{},
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

func TestHost_IsZero(t *testing.T) {
	cases := []struct {
		in       Host
		expected bool
	}{{
		in:       Host{IP: gonet.IPv4(127, 0, 0, 1)},
		expected: false,
	}, {
		in:       Host{Dns: "foo"},
		expected: false,
	}, {
		in:       Host{},
		expected: true,
	}}

	for _, c := range cases {
		t.Run(c.in.String(), func(t *testing.T) {
			actual := c.in.IsZero()
			require.Equal(t, c.expected, actual)
		})
	}
}

func TestHost_Validate(t *testing.T) {
	cases := []struct {
		in       Host
		expected string
	}{{
		in:       Host{IP: gonet.IPv4(127, 0, 0, 1)},
		expected: "",
	}, {
		in:       Host{Dns: "foo"},
		expected: "",
	}, {
		in:       Host{IP: []byte{1, 2, 3}},
		expected: "illegal IP address: ?010203",
	}, {
		in:       Host{},
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

func TestHost_Clone(t *testing.T) {
	cases := []struct {
		in Host
	}{{
		in: Host{IP: gonet.IPv4(127, 0, 0, 1)},
	}, {
		in: Host{Dns: "foo"},
	}}

	for _, c := range cases {
		t.Run(c.in.String(), func(t *testing.T) {
			actual := c.in.Clone()
			require.Equal(t, c.in, actual)
		})
	}
}

func TestHost_IsEqualTo(t *testing.T) {
	cases := []struct {
		left     Host
		right    Host
		expected bool
	}{{
		left:     Host{IP: gonet.IPv4(127, 0, 0, 1)},
		right:    Host{IP: gonet.IPv4(127, 0, 0, 1)},
		expected: true,
	}, {
		left:     Host{IP: gonet.IPv4(127, 0, 0, 1)},
		right:    Host{IP: gonet.IPv4(127, 0, 0, 2)},
		expected: false,
	}, {
		left:     Host{Dns: "foo"},
		right:    Host{Dns: "foo"},
		expected: true,
	}, {
		left:     Host{Dns: "foo"},
		right:    Host{Dns: "foo2"},
		expected: false,
	}, {
		left:     Host{IP: gonet.IPv4(127, 0, 0, 1)},
		right:    Host{Dns: "foo"},
		expected: false,
	}, {
		left:     Host{},
		right:    Host{},
		expected: true,
	}}

	for _, c := range cases {
		t.Run(c.left.String()+"="+c.right.String(), func(t *testing.T) {
			actual := c.left.IsEqualTo(c.right)
			require.Equal(t, c.expected, actual)
		})
	}
}
