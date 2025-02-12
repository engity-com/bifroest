package ssh

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestCipher_supportedBySdk(t *testing.T) {
	for c := range cipher2Name {
		t.Run(c.String(), func(t *testing.T) {
			var sc ssh.Config
			sc.Ciphers = []string{c.String()}
			sc.SetDefaults()
			require.Containsf(t, sc.Ciphers, c.String(), "%v should be supported by SDK, but isn't", c)
		})
	}
}

func TestCipher_implementedByUs(t *testing.T) {
	var sc ssh.Config
	sc.SetDefaults()

	for _, c := range sc.Ciphers {
		t.Run(c, func(t *testing.T) {
			require.Containsf(t, name2Cipher, c, "%v should be implemented, but isn't", c)
		})
	}
}
