package ssh

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/terminal"
)

type terminalAdapterTestSession struct {
	essh.Session
	pty     essh.Pty
	windows chan essh.Window
	mutex   sync.Mutex
	signals chan<- essh.Signal
	closed  atomic.Int32
}

func (this *terminalAdapterTestSession) Pty() (essh.Pty, <-chan essh.Window, bool) {
	return this.pty, this.windows, true
}
func (this *terminalAdapterTestSession) Signals(target chan<- essh.Signal) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.signals = target
}
func (this *terminalAdapterTestSession) Close() error { this.closed.Add(1); return nil }
func (this *terminalAdapterTestSession) send(signal essh.Signal) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.signals <- signal
}

func TestTerminalAdapterPreservesPtyModesPixelsAndSignalNames(t *testing.T) {
	source := &terminalAdapterTestSession{pty: essh.Pty{Term: "xterm", Window: essh.Window{Width: 80, Height: 24, WidthPixels: 800, HeightPixels: 480}, TerminalModes: map[uint8]uint32{53: 1}}, windows: make(chan essh.Window, 1)}
	adapter := NewTerminal(t.Context(), source)
	defer adapter.Stop()
	pty, changes, ok := adapter.Pty()
	require.True(t, ok)
	require.Equal(t, 800, pty.Window.WidthPixels)
	pty.TerminalModes[53] = 2
	second, secondChanges, _ := adapter.Pty()
	require.Equal(t, uint32(1), second.TerminalModes[53])
	require.Equal(t, changes, secondChanges)
	change := essh.Window{Width: 100, Height: 40, WidthPixels: 1000, HeightPixels: 800}
	source.windows <- change
	select {
	case got := <-changes:
		require.Equal(t, TerminalWindow(change), got)
	case <-time.After(time.Second):
		t.Fatal("resize not forwarded")
	}
	receiver := make(chan terminal.Signal, 1)
	adapter.Signals(receiver)
	source.send(essh.SIGTERM)
	select {
	case got := <-receiver:
		require.Equal(t, terminal.Signal("TERM"), got)
	case <-time.After(time.Second):
		t.Fatal("signal not forwarded")
	}
	adapter.Signals(nil)
	close(receiver)
	require.Equal(t, source.pty, SshPty(TerminalPty(source.pty)))
}

func TestTerminalAdapterStopDrainsBlockedControlWorkersWithoutClosingSsh(t *testing.T) {
	source := &terminalAdapterTestSession{windows: make(chan essh.Window, 8)}
	adapter := NewTerminal(t.Context(), source)
	_, changes, _ := adapter.Pty()
	for range 4 {
		source.windows <- essh.Window{Width: 80, Height: 24}
	}
	receiver := make(chan terminal.Signal)
	adapter.Signals(receiver)
	source.send(essh.SIGTERM)
	done := make(chan struct{})
	go func() { adapter.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop blocked on unconsumed control events")
	}
	close(receiver) // Stop joined all sends; channel ownership remains with us.
	for range changes {
	}
	require.Zero(t, source.closed.Load(), "Stop must leave SSH channel open for exit-status delivery")
	require.ErrorIs(t, adapter.Context().Err(), context.Canceled)
	adapter.Stop()
}

func TestTerminalAdapterConcurrentPtyAndStop(t *testing.T) {
	for range 25 {
		source := &terminalAdapterTestSession{windows: make(chan essh.Window)}
		adapter := NewTerminal(t.Context(), source)
		var group sync.WaitGroup
		group.Add(2)
		go func() { defer group.Done(); _, _, _ = adapter.Pty() }()
		go func() { defer group.Done(); adapter.Stop() }()
		group.Wait()
		adapter.Stop()
	}
}

type partialTerminalEnvironmentSession struct{ *terminalAdapterTestSession }

func (*partialTerminalEnvironmentSession) Environ() []string { return []string{"CLIENT=original"} }
func (*partialTerminalEnvironmentSession) ClientEnvironment() []string {
	return []string{"CLIENT=partial-extension"}
}

type layeredTerminalEnvironmentSession struct {
	*partialTerminalEnvironmentSession
	keyEnvironment sys.EnvVars
}

func (this *layeredTerminalEnvironmentSession) AuthorizedKeyEnvironment() sys.EnvVars {
	return this.keyEnvironment
}

func TestTerminalAdapterPreservesLegacyEnvironmentCapabilityBoundary(t *testing.T) {
	partial := &partialTerminalEnvironmentSession{&terminalAdapterTestSession{}}
	adapter := NewTerminal(t.Context(), partial)
	defer adapter.Stop()
	require.Equal(t, []string{"CLIENT=original"}, adapter.ClientEnvironment(), "an incomplete optional capability must retain the old Environ fallback")
	require.Empty(t, adapter.AuthorizedKeyEnvironment())
	complete := &layeredTerminalEnvironmentSession{partial, sys.EnvVars{"KEY": "original"}}
	layered := NewTerminal(t.Context(), complete)
	defer layered.Stop()
	require.Equal(t, []string{"CLIENT=partial-extension"}, layered.ClientEnvironment())
	copy := layered.AuthorizedKeyEnvironment()
	copy["KEY"] = "changed"
	require.Equal(t, sys.EnvVars{"KEY": "original"}, layered.AuthorizedKeyEnvironment())
}
