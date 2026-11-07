package browserfixture

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeProbeFramingPreservesWindowsPathsAndRejectsAmbiguity(t *testing.T) {
	want := Probe{Marker: "web-a", Session: "session", Connection: "connection", SID: "S-1-5-21-1", User: "alice", Profile: `C:\Users\alice`, PID: 123, Pty: true, Columns: 80, Rows: 25, Content: "web-owned"}
	encoded, err := Encode(want)
	require.NoError(t, err)
	got, err := Decode("cmd.exe banner\r\n"+encoded+"\r\nC:\\Users>", "web-a")
	require.NoError(t, err)
	require.Equal(t, want, got)
	_, err = Decode(encoded+encoded, "web-a")
	require.Error(t, err)
	_, err = Decode(encoded, "other")
	require.Error(t, err)
	_, err = Decode(strings.Replace(encoded, Prefix, Prefix+"=", 1), "web-a")
	require.Error(t, err)
}
