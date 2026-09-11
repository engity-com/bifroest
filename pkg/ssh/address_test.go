package ssh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseAddress(t *testing.T) {
	for _, test := range []struct {
		value    string
		expected string
	}{
		{value: "target.example.org", expected: "target.example.org:22"},
		{value: "target.example.org:2222", expected: "target.example.org:2222"},
		{value: "192.0.2.10", expected: "192.0.2.10:22"},
		{value: "2001:db8::1", expected: "[2001:db8::1]:22"},
		{value: "[2001:db8::1]", expected: "[2001:db8::1]:22"},
		{value: "[2001:db8::1]:2222", expected: "[2001:db8::1]:2222"},
		{value: "fe80::1%eth0", expected: "[fe80::1%eth0]:22"},
		{value: "[fe80::1%eth0]", expected: "[fe80::1%eth0]:22"},
		{value: "[fe80::1%eth0]:2222", expected: "[fe80::1%eth0]:2222"},
	} {
		t.Run(test.value, func(t *testing.T) {
			actual, err := ParseAddress(test.value)
			require.NoError(t, err)
			require.Equal(t, test.expected, actual.String())
		})
	}
}

func TestParseAddressRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"", ":22", "target.example.org:", "target.example.org:0", "target.example.org:65536", "[2001:db8::1", "[target.example.org]", "host-a,*.example.org", "host-a,*.example.org:22", "*.example.org", "*.example.org:22", "host example.org", "host example.org:22", "host\u00a0ssh-ed25519\u00a0AAAA", "host\u0085ssh-ed25519\u0085AAAA:22", "#comment", "#comment:22", "@revoked", "@revoked:22", "host@example.org", "host@example.org:22", "fe80::1%bad,zone", "[fe80::1%bad,zone]:22"} {
		t.Run(value, func(t *testing.T) {
			_, err := ParseAddress(value)
			require.Error(t, err)
		})
	}
}
