package test

import (
	"testing"

	rt "github.com/arnodel/golua/runtime"
	"github.com/stretchr/testify/require"
)

// Also run explicitly with -tags=noquotas to verify fail-closed behavior without
// executing any unbounded script in a quota-disabled build.
func TestQuotaCapabilityIsMandatory(t *testing.T) {
	report := run(t, `t:IsEqual(true,true)`)
	if rt.QuotasAvailable {
		require.Zero(t, report.ExitCode())
	} else {
		require.Equal(t, 2, report.ExitCode())
		require.Equal(t, "system", report.Results[0].Category)
	}
}
