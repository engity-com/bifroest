package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWebTerminalOpenHasExactTypedBoundedFields(t *testing.T) {
	valid := `{"type":"open","slug":"Work","accessToken":"proof","task":"shell","pty":{"term":"xterm-256color","columns":80,"rows":24},"environment":["LANG=en_US.UTF-8"]}`
	open, err := parseWebTerminalOpen([]byte(valid))
	require.NoError(t, err)
	require.True(t, open.hasPty)
	require.False(t, open.exec)
	require.Equal(t, []string{"LANG=en_US.UTF-8"}, open.environment)
	for _, raw := range []string{
		`[]`, `{}`, `null`, valid + `{}`, valid + ` false`,
		strings.Replace(valid, `"type":"open"`, `"type":"open","type":"open"`, 1),
		strings.Replace(valid, `"type"`, `"Type"`, 1),
		strings.Replace(valid, `"Work"`, `null`, 1),
		strings.Replace(valid, `"Work"`, `42`, 1),
		strings.Replace(valid, `"task":"shell"`, `"task":"sftp"`, 1),
		strings.Replace(valid, `"task":"shell"`, `"task":"shell","command":""`, 1),
		strings.Replace(valid, `"task":"shell"`, `"task":"exec"`, 1),
		strings.Replace(valid, `"columns":80`, `"columns":80,"columns":90`, 1),
		strings.Replace(valid, `"columns":80`, `"columns":"80"`, 1),
		strings.Replace(valid, `"columns":80`, `"columns":0`, 1),
		strings.Replace(valid, `"columns":80`, `"columns":65536`, 1),
		strings.Replace(valid, `"rows":24`, `"rows":-1`, 1),
		strings.Replace(valid, `"rows":24`, `"rows":1.5`, 1),
		strings.Replace(valid, `"rows":24`, `"rows":24,"widthPixels":4294967296`, 1),
		strings.Replace(valid, `"rows":24`, `"rows":24,"terminalModes":{}`, 1),
		strings.Replace(valid, `xterm-256color`, `bad\u0000term`, 1),
		strings.Replace(valid, `xterm-256color`, strings.Repeat("x", 129), 1),
		strings.Replace(valid, `["LANG=en_US.UTF-8"]`, `null`, 1),
		strings.Replace(valid, `["LANG=en_US.UTF-8"]`, `[null]`, 1),
		strings.Replace(valid, `["LANG=en_US.UTF-8"]`, `["PATH=a","path=b"]`, 1),
		strings.Replace(valid, `["LANG=en_US.UTF-8"]`, `["1BAD=a"]`, 1),
		strings.Replace(valid, `["LANG=en_US.UTF-8"]`, `["KEY=a\u0000b"]`, 1),
		strings.Replace(valid, `["LANG=en_US.UTF-8"]`, `["KEY=`+strings.Repeat("x", 2049)+`"]`, 1),
		strings.Replace(valid, `"slug"`, `"sessionId"`, 1),
		strings.Replace(valid, `"slug"`, `"privateKey"`, 1),
		strings.Replace(valid, `"slug"`, `"passphrase"`, 1),
		strings.Replace(valid, `"Work"`, string([]byte{'"', 255, '"'}), 1),
	} {
		_, err := parseWebTerminalOpen([]byte(raw))
		require.Error(t, err, "must reject %q", raw)
	}
	for _, command := range []string{strings.Repeat("x", 4097), "a\x00b"} {
		raw, err := json.Marshal(map[string]string{"type": "open", "slug": "", "accessToken": "proof", "task": "exec", "command": command})
		require.NoError(t, err)
		_, err = parseWebTerminalOpen(raw)
		require.Error(t, err)
	}
}

func TestWebTerminalInboundBudgetsCannotBeRenewedByFrames(t *testing.T) {
	for _, mode := range []string{"messages", "controls", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			stream := &webTerminalStream{budgetSince: time.Now()}
			switch mode {
			case "messages":
				stream.budgetMessages = webTerminalMessagesPerSecond
			case "controls":
				stream.budgetControls = webTerminalControlsPerSecond
			case "bytes":
				stream.budgetBytes = webTerminalBytesPerSecond
			}
			require.Error(t, stream.accountInbound(1, true))
			stream.budgetSince = time.Now().Add(-time.Second)
			require.NoError(t, stream.accountInbound(1, true))
		})
	}
}
