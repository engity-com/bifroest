package https

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCertificateRenewalDateAdaptsToTheEffectiveLifetime(t *testing.T) {
	start := time.Date(2026, time.October, 22, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name              string
		lifetime, advance time.Duration
	}{
		{"ninety days", 90 * 24 * time.Hour, 60 * 24 * time.Hour},
		{"long lifetime capped at thirty days before expiry", 365 * 24 * time.Hour, 335 * 24 * time.Hour},
		{"short lived", 6 * time.Hour, 4 * time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate := &preparedCertificate{notBefore: start, notAfter: start.Add(test.lifetime)}
			require.Equal(t, start.Add(test.advance), certificateRenewalAt(certificate))
		})
	}
}
