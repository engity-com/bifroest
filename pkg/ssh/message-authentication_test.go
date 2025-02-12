package ssh

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestMessageAuthentication_supportedBySdk(t *testing.T) {
	for c := range messageAuthentication2Name {
		t.Run(c.String(), func(t *testing.T) {
			var sc ssh.Config
			sc.MACs = []string{c.String()}
			sc.SetDefaults()
			require.Containsf(t, sc.MACs, c.String(), "%v should be supported by SDK, but isn't", c)
		})
	}
}

func TestMessageAuthentication_implementedByUs(t *testing.T) {
	var sc ssh.Config
	sc.SetDefaults()

	for _, c := range sc.MACs {
		t.Run(c, func(t *testing.T) {
			require.Containsf(t, name2MessageAuthentication, c, "%v should be implemented, but isn't", c)
		})
	}
}
