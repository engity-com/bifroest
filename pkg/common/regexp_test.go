package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegexpMatchesEntireString(t *testing.T) {
	pattern := MustNewRegexp("sftp|netconf")
	require.True(t, pattern.MatchEntireString("sftp"))
	require.True(t, pattern.MatchEntireString("netconf"))
	require.False(t, pattern.MatchEntireString("not-netconf"))
	require.False(t, pattern.MatchEntireString("sftp-server"))
	require.True(t, pattern.MatchString("not-netconf"))

	pattern = MustNewRegexp("a|ab")
	require.True(t, pattern.MatchEntireString("ab"))
	pattern = MustNewRegexp("")
	require.False(t, pattern.MatchEntireString("sftp"))
}
