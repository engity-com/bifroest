package ssh

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestKeyExchange_supportedBySdk(t *testing.T) {
	for c := range keyExchange2Name {
		t.Run(c.String(), func(t *testing.T) {
			var sc ssh.Config
			sc.KeyExchanges = []string{c.String()}
			sc.SetDefaults()
			require.Containsf(t, sc.KeyExchanges, c.String(), "%v should be supported by SDK, but isn't", c)
		})
	}
}

func TestKeyExchange_implementedByUs(t *testing.T) {
	var sc ssh.Config
	sc.SetDefaults()

	for _, c := range sc.KeyExchanges {
		t.Run(c, func(t *testing.T) {
			require.Containsf(t, name2KeyExchange, c, "%v should be implemented, but isn't", c)
		})
	}
}
