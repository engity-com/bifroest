//go:build linux || darwin

package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sys/unix"

	cliformat "github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
)

func consoleTestTTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, terminal, err := pty.Open()
	require.NoError(t, err)
	t.Cleanup(func() { _ = master.Close() })
	t.Cleanup(func() { _ = terminal.Close() })
	return master, terminal
}

func consoleTestTTYState(t *testing.T, terminal *os.File) (unix.Termios, int) {
	t.Helper()
	raw, err := terminal.SyscallConn()
	require.NoError(t, err)
	var mode *unix.Termios
	var flags int
	var modeErr, flagsErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		mode, modeErr = readConsoleTermios(int(fd))
		flags, flagsErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
	}))
	require.NoError(t, modeErr)
	require.NoError(t, flagsErr)
	return *mode, flags
}

func requireConsoleTestTTYState(t *testing.T, terminal *os.File, original unix.Termios, flags int) {
	t.Helper()
	after, afterFlags := consoleTestTTYState(t, terminal)
	require.Equal(t, original, after, "original terminal mode must be restored")
	require.Equal(t, flags, afterFlags, "borrowed stdin flags must remain unchanged")
}

func startConsoleTestPassword(ctx context.Context, prompt string) <-chan consoleTestResult {
	done := make(chan consoleTestResult, 1)
	go func() {
		line, err := readManagementPassword(ctx, prompt)
		done <- consoleTestResult{line, err}
	}()
	return done
}

func TestManagementConsolePasswordPreservesBorrowedTerminal(t *testing.T) {
	master, terminal := consoleTestTTY(t)
	original, flags := consoleTestTTYState(t, terminal)
	output := newConsoleTestOutput()
	var stdout bytes.Buffer
	ctx, cancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, &stdout, output))
	defer cancel()
	done := startConsoleTestPassword(ctx, "Password: ")
	output.await(t, "Password: ")
	mode, activeFlags := consoleTestTTYState(t, terminal)
	require.Zero(t, mode.Lflag&(unix.ECHO|unix.ECHONL))
	require.Equal(t, flags, activeFlags)
	_, err := master.Write([]byte("sëcretX\x7f\n"))
	require.NoError(t, err)
	result := awaitConsoleTestResult(t, done)
	require.NoError(t, result.err)
	require.Equal(t, "sëcret", string(result.line))
	clear(result.line)
	require.Equal(t, "Password: \n", output.String())
	require.Empty(t, stdout.String())
	requireConsoleTestTTYState(t, terminal, original, flags)
	ready := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
	_, err = unix.Poll(ready, 10)
	require.NoError(t, err)
	require.Zero(t, ready[0].Revents, "hidden input must not echo to its terminal")

	// The caller still owns a working stdin after authentication finishes.
	_, err = master.Write([]byte("still usable\n"))
	require.NoError(t, err)
	var buffer [64]byte
	n, err := terminal.Read(buffer[:])
	require.NoError(t, err)
	require.Equal(t, "still usable\n", string(buffer[:n]))
}

func TestManagementConsolePreservesLongAnswers(t *testing.T) {
	for _, echo := range []bool{false, true} {
		for _, test := range []struct {
			name  string
			input string
			over  bool
		}{
			{"old boundary", strings.Repeat("x", 4095), false},
			{"past old boundary", strings.Repeat("x", 4096), false},
			{"review repro", strings.Repeat("x", 5000), false},
			{"long unicode", strings.Repeat("é😀", 1000), false},
			{"at limit", strings.Repeat("x", maximumConsoleInputBytes), false},
			{"unicode at limit", strings.Repeat("x", maximumConsoleInputBytes-4) + "😀", false},
			{"over limit", strings.Repeat("x", maximumConsoleInputBytes+1), true},
			{"unicode over limit", strings.Repeat("x", maximumConsoleInputBytes-3) + "😀", true},
		} {
			t.Run(fmt.Sprintf("echo=%t/%s", echo, test.name), func(t *testing.T) {
				master, terminal := consoleTestTTY(t)
				original, flags := consoleTestTTYState(t, terminal)
				output := newConsoleTestOutput()
				var stdout bytes.Buffer
				ctx, cancel := context.WithTimeout(cli.ContextWithStdio(t.Context(), terminal, &stdout, output), 5*time.Second)
				defer cancel()
				done := make(chan consoleTestResult, 1)
				go func() {
					line, err := readManagementLine(ctx, "Long answer: ", echo)
					done <- consoleTestResult{line, err}
				}()
				output.await(t, "Long answer: ")
				_, err := io.WriteString(master, test.input+"\n")
				require.NoError(t, err)
				result := awaitConsoleTestResult(t, done)
				defer clear(result.line)
				if test.over {
					require.ErrorContains(t, result.err, "input exceeds")
					require.Nil(t, result.line, "oversized answers must not expose their prefix")
				} else {
					require.NoError(t, result.err)
					require.Equal(t, len(test.input), len(result.line), "terminal answer must not be silently truncated")
					require.True(t, bytes.Equal([]byte(test.input), result.line), "terminal answer must remain unchanged")
					if echo {
						require.True(t, output.String() == "Long answer: "+test.input+"\n", "visible answers must echo unchanged to stderr")
					}
				}
				if !echo {
					require.Equal(t, "Long answer: \n", output.String())
				}
				require.Empty(t, stdout.Bytes())
				requireConsoleTestTTYState(t, terminal, original, flags)
			})
		}
	}
}

func TestManagementConsoleEditsUnicodeAnswers(t *testing.T) {
	for _, echo := range []bool{false, true} {
		for _, edit := range []string{"erase", "kill", "word erase"} {
			t.Run(fmt.Sprintf("echo=%t/%s", echo, edit), func(t *testing.T) {
				master, terminal := consoleTestTTY(t)
				original, flags := consoleTestTTYState(t, terminal)
				var input, expected string
				switch edit {
				case "erase":
					input = "së😀" + string(original.Cc[unix.VERASE]) + "X\n"
					expected = "sëX"
				case "kill":
					input = "discard sëcret😀" + string(original.Cc[unix.VKILL]) + "fresh\n"
					expected = "fresh"
				case "word erase":
					if original.Lflag&unix.IEXTEN == 0 || original.Cc[unix.VWERASE] == disabledConsoleControl {
						t.Skip("terminal word erase is disabled")
					}
					input = "first é😀 " + string(original.Cc[unix.VWERASE]) + "last\n"
					expected = "first last"
				}
				output := newConsoleTestOutput()
				ctx, cancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, io.Discard, output))
				defer cancel()
				done := make(chan consoleTestResult, 1)
				go func() {
					line, err := readManagementLine(ctx, "Answer: ", echo)
					done <- consoleTestResult{line, err}
				}()
				output.await(t, "Answer: ")
				_, err := io.WriteString(master, input)
				require.NoError(t, err)
				result := awaitConsoleTestResult(t, done)
				defer clear(result.line)
				require.NoError(t, result.err)
				require.Equal(t, expected, string(result.line))
				tail := result.line[len(result.line):cap(result.line)]
				require.Equal(t, len(tail), bytes.Count(tail, []byte{0}), "erased secret bytes must be cleared")
				if !echo {
					require.Equal(t, "Answer: \n", output.String())
				}
				requireConsoleTestTTYState(t, terminal, original, flags)
			})
		}
	}
}

func TestManagementConsoleCancellationDiscardsUnsubmittedSecret(t *testing.T) {
	master, terminal := consoleTestTTY(t)
	original, flags := consoleTestTTYState(t, terminal)
	output := newConsoleTestOutput()
	ctx, cancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, io.Discard, output))
	defer cancel()
	done := startConsoleTestPassword(ctx, "First: ")
	output.await(t, "First: ")
	_, err := master.Write([]byte("discard this secret"))
	require.NoError(t, err)
	cancel()
	result := awaitConsoleTestResult(t, done)
	require.ErrorIs(t, result.err, context.Canceled)
	require.Nil(t, result.line)
	requireConsoleTestTTYState(t, terminal, original, flags)

	ctx = cli.ContextWithStdio(t.Context(), terminal, io.Discard, output)
	done = startConsoleTestPassword(ctx, "Second: ")
	output.await(t, "Second: ")
	_, err = master.Write([]byte("fresh\n"))
	require.NoError(t, err)
	result = awaitConsoleTestResult(t, done)
	require.NoError(t, result.err)
	require.Equal(t, "fresh", string(result.line))
	clear(result.line)
	requireConsoleTestTTYState(t, terminal, original, flags)
}

func TestManagementConsoleQueuedPromptCanBeCanceled(t *testing.T) {
	master, terminal := consoleTestTTY(t)
	firstOutput, secondOutput := newConsoleTestOutput(), newConsoleTestOutput()
	firstCtx, firstCancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, io.Discard, firstOutput))
	defer firstCancel()
	first := startConsoleTestPassword(firstCtx, "Active: ")
	firstOutput.await(t, "Active: ")
	secondCtx, secondCancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, io.Discard, secondOutput))
	defer secondCancel()
	second := startConsoleTestPassword(secondCtx, "Queued: ")
	secondCancel()
	result := awaitConsoleTestResult(t, second)
	require.ErrorIs(t, result.err, context.Canceled)
	require.Empty(t, secondOutput.String())
	mode, _ := consoleTestTTYState(t, terminal)
	require.Zero(t, mode.Lflag&unix.ECHO, "queued cancellation must not restore the active prompt's mode")
	_, err := master.Write([]byte("active secret\n"))
	require.NoError(t, err)
	result = awaitConsoleTestResult(t, first)
	require.NoError(t, result.err)
	require.Equal(t, "active secret", string(result.line))
	clear(result.line)
}

func TestManagementConsoleKeyboardInteractiveMixedEcho(t *testing.T) {
	master, terminal := consoleTestTTY(t)
	original, flags := consoleTestTTYState(t, terminal)
	output := newConsoleTestOutput()
	ctx, cancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, io.Discard, output))
	defer cancel()
	var answers []string
	done := make(chan consoleTestResult, 1)
	go func() {
		var err error
		answers, err = keyboardInteractive(ctx, "admin", "Answer both questions", []string{"Login: ", "Token: "}, []bool{true, false})
		done <- consoleTestResult{err: err}
	}()
	output.await(t, "Login: ")
	mode, _ := consoleTestTTYState(t, terminal)
	require.Zero(t, mode.Lflag&(unix.ECHO|unix.ICANON), "visible input is echoed by the application, not the kernel")
	_, err := master.Write([]byte("alice\n"))
	require.NoError(t, err)
	output.await(t, "Token: ")
	mode, _ = consoleTestTTYState(t, terminal)
	require.Zero(t, mode.Lflag&unix.ECHO)
	_, err = master.Write([]byte("private token\n"))
	require.NoError(t, err)
	require.NoError(t, awaitConsoleTestResult(t, done).err)
	require.Equal(t, []string{"alice", "private token"}, answers)
	require.Contains(t, output.String(), "Login: alice\nToken: ")
	require.NotContains(t, output.String(), "private token")
	requireConsoleTestTTYState(t, terminal, original, flags)
}

type consoleTestShortWriter struct{}

func (consoleTestShortWriter) Write([]byte) (int, error) { return 0, nil }

func TestManagementConsoleRestoresTerminalOnPromptFailureAndEOF(t *testing.T) {
	master, terminal := consoleTestTTY(t)
	original, flags := consoleTestTTYState(t, terminal)
	ctx := cli.ContextWithStdio(t.Context(), terminal, io.Discard, consoleTestShortWriter{})
	line, err := readManagementPassword(ctx, "Password: ")
	require.ErrorIs(t, err, io.ErrShortWrite)
	require.Nil(t, line)
	requireConsoleTestTTYState(t, terminal, original, flags)
	output := newConsoleTestOutput()
	ctx, cancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, io.Discard, output))
	defer cancel()
	done := startConsoleTestPassword(ctx, "EOF: ")
	output.await(t, "EOF: ")
	_, err = master.Write([]byte{original.Cc[unix.VEOF]})
	require.NoError(t, err)
	result := awaitConsoleTestResult(t, done)
	require.ErrorIs(t, result.err, io.EOF)
	require.Nil(t, result.line)
	requireConsoleTestTTYState(t, terminal, original, flags)
}

func TestManagementConsoleDoesNotConsumeNextAnswer(t *testing.T) {
	for _, echo := range []bool{false, true} {
		for _, long := range []bool{false, true} {
			t.Run(fmt.Sprintf("echo=%t/long=%t", echo, long), func(t *testing.T) {
				master, terminal := consoleTestTTY(t)
				original, flags := consoleTestTTYState(t, terminal)
				output := newConsoleTestOutput()
				ctx, cancel := context.WithTimeout(cli.ContextWithStdio(t.Context(), terminal, io.Discard, output), 5*time.Second)
				defer cancel()
				first, second := "first", "second"
				if long {
					first, second = strings.Repeat("é😀", 1000), strings.Repeat("sëcond", 1000)
				}
				var answers []string
				done := make(chan consoleTestResult, 1)
				go func() {
					var err error
					answers, err = keyboardInteractive(ctx, "admin", "", []string{"First: ", "Second: "}, []bool{echo, !echo})
					done <- consoleTestResult{err: err}
				}()
				output.await(t, "First: ")
				_, err := io.WriteString(master, first+"\n"+second+"\n")
				require.NoError(t, err)
				require.NoError(t, awaitConsoleTestResult(t, done).err)
				require.Len(t, answers, 2)
				require.True(t, answers[0] == first && answers[1] == second, "queued answers must not be truncated or consumed by the previous prompt")
				requireConsoleTestTTYState(t, terminal, original, flags)
			})
		}
	}
}

type consoleTestChallengeOutput struct {
	*consoleTestOutput
	terminal *os.File
}

func (this consoleTestChallengeOutput) Write(value []byte) (int, error) {
	if string(value) == "\n" {
		raw, err := this.terminal.SyscallConn()
		if err != nil {
			return 0, err
		}
		var mode *unix.Termios
		var modeErr error
		if err := raw.Control(func(fd uintptr) { mode, modeErr = readConsoleTermios(int(fd)) }); err != nil {
			return 0, err
		}
		if modeErr != nil {
			return 0, modeErr
		}
		if mode.Lflag&unix.ICANON != 0 {
			return 0, fmt.Errorf("terminal restored between keyboard-interactive questions")
		}
	}
	return this.consoleTestOutput.Write(value)
}

func TestManagementConsoleKeepsTerminalForEntireChallenge(t *testing.T) {
	master, terminal := consoleTestTTY(t)
	original, flags := consoleTestTTYState(t, terminal)
	output := newConsoleTestOutput()
	ctx, cancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, io.Discard, consoleTestChallengeOutput{output, terminal}))
	defer cancel()
	done := make(chan consoleTestResult, 1)
	var answers []string
	go func() {
		var err error
		answers, err = keyboardInteractive(ctx, "admin", "", []string{"First: ", "Second: "}, []bool{false, false})
		done <- consoleTestResult{err: err}
	}()
	output.await(t, "First: ")
	_, err := io.WriteString(master, "first\nsecond\n")
	require.NoError(t, err)
	require.NoError(t, awaitConsoleTestResult(t, done).err)
	require.Equal(t, []string{"first", "second"}, answers)
	requireConsoleTestTTYState(t, terminal, original, flags)
}

func TestManagementConsoleCancellationDiscardsEntireChallenge(t *testing.T) {
	master, terminal := consoleTestTTY(t)
	original, flags := consoleTestTTYState(t, terminal)
	output := newConsoleTestOutput()
	ctx, cancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, io.Discard, output))
	defer cancel()
	done := make(chan consoleTestResult, 1)
	var answers []string
	go func() {
		var err error
		answers, err = keyboardInteractive(ctx, "admin", "", []string{"First: ", "Second: "}, []bool{false, false})
		done <- consoleTestResult{err: err}
	}()
	output.await(t, "First: ")
	_, err := io.WriteString(master, "first answer\n")
	require.NoError(t, err)
	output.await(t, "Second: ")
	_, err = io.WriteString(master, "discard this secret")
	require.NoError(t, err)
	cancel()
	require.ErrorIs(t, awaitConsoleTestResult(t, done).err, context.Canceled)
	require.Nil(t, answers, "a failed challenge must not return earlier answers")
	requireConsoleTestTTYState(t, terminal, original, flags)

	ctx = cli.ContextWithStdio(t.Context(), terminal, io.Discard, output)
	fresh := startConsoleTestPassword(ctx, "Fresh: ")
	output.await(t, "Fresh: ")
	_, err = io.WriteString(master, "fresh\n")
	require.NoError(t, err)
	result := awaitConsoleTestResult(t, fresh)
	defer clear(result.line)
	require.NoError(t, result.err)
	require.Equal(t, "fresh", string(result.line))
	requireConsoleTestTTYState(t, terminal, original, flags)
}

func TestManagementConsoleHonorsConfiguredAndDisabledControls(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("disabled=%t", disabled), func(t *testing.T) {
			master, terminal := consoleTestTTY(t)
			mode, _ := consoleTestTTYState(t, terminal)
			mode.Lflag |= unix.IEXTEN
			mode.Cc[unix.VERASE], mode.Cc[unix.VKILL], mode.Cc[unix.VWERASE] = '#', '@', '!'
			input, expected := "a#b@first é😀 !last\n", "first last"
			if disabled {
				for _, index := range []int{unix.VEOF, unix.VERASE, unix.VKILL, unix.VWERASE} {
					mode.Cc[index] = disabledConsoleControl
				}
				input = string([]byte{'a', disabledConsoleControl, 'b', '\n'})
				expected = input[:len(input)-1]
			}
			raw, err := terminal.SyscallConn()
			require.NoError(t, err)
			var modeErr error
			require.NoError(t, raw.Control(func(fd uintptr) { modeErr = writeConsoleTermios(int(fd), &mode, false) }))
			require.NoError(t, modeErr)
			original, flags := consoleTestTTYState(t, terminal)
			output := newConsoleTestOutput()
			ctx, cancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, io.Discard, output))
			defer cancel()
			done := startConsoleTestPassword(ctx, "Answer: ")
			output.await(t, "Answer: ")
			_, err = io.WriteString(master, input)
			require.NoError(t, err)
			result := awaitConsoleTestResult(t, done)
			defer clear(result.line)
			require.NoError(t, result.err)
			require.Equal(t, expected, string(result.line))
			require.Equal(t, "Answer: \n", output.String())
			requireConsoleTestTTYState(t, terminal, original, flags)
		})
	}
}

type consoleTestEchoFailure struct{ *consoleTestOutput }

func (this consoleTestEchoFailure) Write(value []byte) (int, error) {
	if string(value) == "Answer: " {
		return this.consoleTestOutput.Write(value)
	}
	return 0, io.ErrClosedPipe
}

func TestManagementConsoleRestoresTerminalOnEchoFailure(t *testing.T) {
	master, terminal := consoleTestTTY(t)
	original, flags := consoleTestTTYState(t, terminal)
	output := newConsoleTestOutput()
	ctx, cancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, io.Discard, consoleTestEchoFailure{output}))
	defer cancel()
	done := make(chan consoleTestResult, 1)
	go func() {
		line, err := readManagementLine(ctx, "Answer: ", true)
		done <- consoleTestResult{line, err}
	}()
	output.await(t, "Answer: ")
	_, err := io.WriteString(master, "answer\n")
	require.NoError(t, err)
	result := awaitConsoleTestResult(t, done)
	require.ErrorIs(t, result.err, io.ErrClosedPipe)
	require.Nil(t, result.line)
	require.Equal(t, "Answer: ", output.String())
	requireConsoleTestTTYState(t, terminal, original, flags)
}

func TestManagementConsoleDiscardsPartialAnswerOnEOF(t *testing.T) {
	master, terminal := consoleTestTTY(t)
	original, flags := consoleTestTTYState(t, terminal)
	output := newConsoleTestOutput()
	ctx, cancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, io.Discard, output))
	defer cancel()
	done := startConsoleTestPassword(ctx, "Answer: ")
	output.await(t, "Answer: ")
	_, err := master.Write(append([]byte("partial answer"), original.Cc[unix.VEOF]))
	require.NoError(t, err)
	result := awaitConsoleTestResult(t, done)
	require.ErrorIs(t, result.err, io.EOF)
	require.Nil(t, result.line)
	require.Equal(t, "Answer: \n", output.String())
	requireConsoleTestTTYState(t, terminal, original, flags)
}

func TestManagementClientUnlocksEncryptedIdentityFromContextTerminal(t *testing.T) {
	for name, passphrase := range map[string]string{
		"short": "key passphrase",
		"long":  strings.Repeat("é😀", 1000),
	} {
		t.Run(name, func(t *testing.T) { testManagementClientUnlocksEncryptedIdentity(t, passphrase) })
	}
}

func testManagementClientUnlocksEncryptedIdentity(t *testing.T, passphrase string) {
	t.Helper()
	target, serverDone := managementClientTestServer(t, transport.WireCommand, func(channel ssh.Channel, _ []string) error {
		if err := cliformat.WriteFlowList(channel, cliformat.WireCbor, []model.FlowSummary{{Name: "authenticated"}}); err != nil {
			return err
		}
		_, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return err
	})
	settings, err := resolve(target)
	require.NoError(t, err)
	content, err := os.ReadFile(settings.identities[0])
	require.NoError(t, err)
	key, err := ssh.ParseRawPrivateKey(content)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "test", []byte(passphrase))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(settings.identities[0], pem.EncodeToMemory(block), 0600))
	master, terminal := consoleTestTTY(t)
	original, flags := consoleTestTTYState(t, terminal)
	output := newConsoleTestOutput()
	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(cli.ContextWithStdio(t.Context(), terminal, &stdout, output), 5*time.Second)
	defer cancel()
	done := make(chan consoleTestResult, 1)
	go func() { done <- consoleTestResult{err: target.Run(ctx, "flow", "ls", "--format=json")} }()
	output.await(t, "Passphrase for SSH key")
	_, err = io.WriteString(master, passphrase+"\n")
	require.NoError(t, err)
	require.NoError(t, awaitConsoleTestResult(t, done).err)
	require.NoError(t, <-serverDone)
	require.Contains(t, stdout.String(), "authenticated")
	require.NotContains(t, output.String(), passphrase)
	requireConsoleTestTTYState(t, terminal, original, flags)
}

func TestManagementClientInteractiveAuthenticationUsesCancelableContextTerminal(t *testing.T) {
	for name, answer := range map[string]string{
		"short": "authentication secret",
		"long":  strings.Repeat("é😀", 1000),
	} {
		t.Run(name, func(t *testing.T) { testManagementClientInteractiveAuthentication(t, answer) })
	}
}

func testManagementClientInteractiveAuthentication(t *testing.T, answer string) {
	t.Helper()
	for _, keyboard := range []bool{false, true} {
		for _, interrupt := range []bool{false, true} {
			t.Run(fmt.Sprintf("keyboard=%v/cancel=%v", keyboard, interrupt), func(t *testing.T) {
				target, serverDone := managementSSHAuthTestServer(t, transport.WireCommand, func(channel ssh.Channel) error {
					if _, err := transport.DecodeWireRequest(channel); err != nil {
						return err
					}
					if err := cliformat.WriteFlowList(channel, cliformat.WireCbor, []model.FlowSummary{{Name: "authenticated"}}); err != nil {
						return err
					}
					_, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return err
				}, func(config *ssh.ServerConfig) {
					config.PublicKeyCallback = nil
					if keyboard {
						config.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
							answers, err := challenge("admin", "Authentication required", []string{"SSH token: "}, []bool{false})
							if err != nil {
								return nil, err
							}
							if len(answers) != 1 || answers[0] != answer {
								return nil, fmt.Errorf("unexpected authentication answer")
							}
							return nil, nil
						}
					} else {
						config.PasswordCallback = func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
							if string(password) != answer {
								return nil, fmt.Errorf("unexpected password")
							}
							return nil, nil
						}
					}
				})
				master, terminal := consoleTestTTY(t)
				original, flags := consoleTestTTYState(t, terminal)
				output := newConsoleTestOutput()
				var stdout bytes.Buffer
				ctx, cancel := context.WithTimeout(cli.ContextWithStdio(t.Context(), terminal, &stdout, output), 5*time.Second)
				defer cancel()
				done := make(chan consoleTestResult, 1)
				go func() { done <- consoleTestResult{err: target.Run(ctx, "flow", "ls", "--format=json")} }()
				prompt := "SSH password: "
				if keyboard {
					prompt = "SSH token: "
				}
				output.await(t, prompt)
				if interrupt {
					cancel()
					require.Error(t, awaitConsoleTestResult(t, done).err)
					require.Error(t, <-serverDone)
					require.Empty(t, stdout.String())
				} else {
					_, err := io.WriteString(master, answer+"\n")
					require.NoError(t, err)
					require.NoError(t, awaitConsoleTestResult(t, done).err)
					require.NoError(t, <-serverDone)
					require.Contains(t, stdout.String(), "authenticated")
				}
				require.NotContains(t, output.String(), answer)
				requireConsoleTestTTYState(t, terminal, original, flags)
			})
		}
	}
}

func TestManagementConsoleInterruptProcess(t *testing.T) {
	if config := os.Getenv("BIFROEST_TEST_CONSOLE_INTERRUPT_CONFIG"); config != "" {
		original, flags := consoleTestTTYState(t, os.Stdin)
		ctx, cancel := signal.NotifyContext(t.Context(), os.Interrupt)
		defer cancel()
		ctx = cli.ContextWithStdio(ctx, os.Stdin, os.Stdout, os.Stderr)
		err := (Target{Host: "cancel-test", SSHConfigFile: config}).Run(ctx, "flow", "ls")
		require.True(t, errors.Is(err, context.Canceled), "expected interrupted authentication, got %v", err)
		// Darwin revokes the controlling PTY when this session exits, so check
		// restoration here while the child still owns a usable terminal.
		requireConsoleTestTTYState(t, os.Stdin, original, flags)
		return
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "test", []byte("unused passphrase"))
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	directory := t.TempDir()
	identity, hosts, config := filepath.Join(directory, "identity"), filepath.Join(directory, "known_hosts"), filepath.Join(directory, "config")
	require.NoError(t, os.WriteFile(identity, pem.EncodeToMemory(block), 0600))
	require.NoError(t, os.WriteFile(hosts, []byte(knownhosts.Line([]string{"127.0.0.1"}, signer.PublicKey())+"\n"), 0600))
	require.NoError(t, os.WriteFile(config, fmt.Appendf(nil, "Host cancel-test\n HostName 127.0.0.1\n User admin\n IdentityAgent none\n IdentityFile %s\n UserKnownHostsFile %s\n", identity, hosts), 0600))
	binary, err := os.Executable()
	require.NoError(t, err)
	for _, keyboard := range []bool{false, true} {
		name := "SIGINT"
		if keyboard {
			name = "CtrlC"
		}
		t.Run(name, func(t *testing.T) {
			master, terminal := consoleTestTTY(t)
			original, _ := consoleTestTTYState(t, terminal)
			output := newConsoleTestOutput()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, "-test.run=^TestManagementConsoleInterruptProcess$")
			command.Env = append(os.Environ(), "BIFROEST_TEST_CONSOLE_INTERRUPT_CONFIG="+config)
			command.Stdin, command.Stderr = terminal, output
			var stdout bytes.Buffer
			command.Stdout = &stdout
			command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			require.NoError(t, command.Start())
			done := make(chan consoleTestResult, 1)
			go func() { done <- consoleTestResult{err: command.Wait()} }()
			output.await(t, "Passphrase for SSH key")
			if keyboard {
				_, err = master.Write([]byte{original.Cc[unix.VINTR]})
			} else {
				err = command.Process.Signal(os.Interrupt)
			}
			require.NoError(t, err)
			result := awaitConsoleTestResult(t, done)
			require.NoError(t, result.err, "child output: %s; stderr: %s", stdout.String(), output.String())
			require.NoError(t, ctx.Err(), "authentication must finish before the watchdog kills it")
		})
	}
}
