package terminal

import "testing"

func TestClonePtyDoesNotShareMutableModes(t *testing.T) {
	initial := Pty{Term: "xterm", Window: Window{Width: 80, Height: 24}, TerminalModes: map[uint8]uint32{53: 1}}
	copy := ClonePty(initial)
	copy.TerminalModes[53] = 2
	if initial.TerminalModes[53] != 1 {
		t.Fatal("terminal snapshots share mutable modes")
	}
	if ClonePty(Pty{}).TerminalModes != nil {
		t.Fatal("absent terminal modes must remain absent")
	}
}
