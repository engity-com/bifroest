package conpty

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPinnedPayloadsAreUnmodifiedLibrariesForEachArchitecture(t *testing.T) {
	require.Len(t, Payloads, 3)
	for _, payload := range Payloads {
		t.Run(payload.Arch, func(t *testing.T) {
			raw, err := os.ReadFile(payload.Filename())
			require.NoError(t, err)
			require.NoError(t, payload.Verify(raw))
			changed := bytes.Clone(raw)
			changed[len(changed)-1] ^= 1
			require.ErrorContains(t, payload.Verify(changed), "digest mismatch")
			wrongMachine := payload
			wrongMachine.Machine = 0
			require.ErrorContains(t, wrongMachine.Verify(raw), "unexpected machine")
		})
	}
	require.Contains(t, License, "Copyright (c) Microsoft Corporation")
	require.Contains(t, License, "Permission is hereby granted")
}
