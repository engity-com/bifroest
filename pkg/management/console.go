package management

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	cli "github.com/echocat/cli4g"
	"golang.org/x/term"
)

// Terminal modes are shared by all handles of the same terminal. Serialize
// prompts while allowing a queued invocation to be canceled before acquiring it.
var managementConsoleGate = make(chan struct{}, 1)

const maximumConsoleInputBytes = 64 << 10

func managementTerminalInput(ctx context.Context) (*os.File, error) {
	input, ok := cli.StdinOfContext(ctx).(*os.File)
	if !ok {
		return nil, fmt.Errorf("SSH authentication needs a terminal or an SSH agent/usable identity file")
	}
	raw, err := input.SyscallConn()
	if err != nil {
		return nil, err
	}
	terminal := false
	if err := raw.Control(func(fd uintptr) { terminal = term.IsTerminal(int(fd)) }); err != nil {
		return nil, err
	}
	if !terminal {
		return nil, fmt.Errorf("SSH authentication needs a terminal or an SSH agent/usable identity file")
	}
	return input, nil
}

func readManagementPassword(ctx context.Context, prompt string) ([]byte, error) {
	return readManagementLine(ctx, prompt, false)
}

func readManagementLine(ctx context.Context, prompt string, echo bool) (line []byte, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	input, err := managementTerminalInput(ctx)
	if err != nil {
		return nil, err
	}
	output := cli.StderrOfContext(ctx)
	if output == nil {
		return nil, fmt.Errorf("SSH authentication prompt output is unavailable")
	}
	select {
	case managementConsoleGate <- struct{}{}:
		defer func() { <-managementConsoleGate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := input.SyscallConn()
	if err != nil {
		return nil, err
	}
	var console *consoleInput
	var openErr error
	if err := raw.Control(func(fd uintptr) { console, openErr = openConsoleInput(fd, echo, output) }); err != nil {
		return nil, err
	}
	if openErr != nil {
		return nil, openErr
	}
	defer func() {
		resultErr = errors.Join(resultErr, console.close(resultErr != nil))
		if !echo || resultErr != nil {
			resultErr = errors.Join(resultErr, writeConsoleText(output, "\n"))
		}
		if resultErr != nil {
			clear(line)
			line = nil
		}
	}()
	if err := writeConsoleText(output, prompt); err != nil {
		return nil, err
	}
	return console.readLine(ctx)
}

func writeConsoleText(output io.Writer, text string) error {
	written, err := io.WriteString(output, text)
	if err == nil && written != len(text) {
		return io.ErrShortWrite
	}
	return err
}

func keyboardInteractive(ctx context.Context, _ string, instructions string, questions []string, echos []bool) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := managementTerminalInput(ctx); err != nil {
		return nil, err
	}
	output := cli.StderrOfContext(ctx)
	if output == nil {
		return nil, fmt.Errorf("SSH authentication prompt output is unavailable")
	}
	if instructions != "" {
		if err := writeConsoleText(output, instructions+"\n"); err != nil {
			return nil, err
		}
	}
	answers := make([]string, 0, len(questions))
	for index, question := range questions {
		echo := index >= len(echos) || echos[index]
		line, err := readManagementLine(ctx, question, echo)
		if err != nil {
			clear(answers)
			return nil, err
		}
		answers = append(answers, string(line))
		clear(line)
	}
	return answers, nil
}
