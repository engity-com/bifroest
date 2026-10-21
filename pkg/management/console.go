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
	console, err := openManagementConsole(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = console.close(resultErr)
		if resultErr != nil {
			clear(line)
			line = nil
		}
	}()
	return console.readLine(ctx, prompt, echo)
}

// managementConsole owns the terminal mode and prompt gate for one complete
// authentication interaction, including every question in a challenge.
type managementConsole struct {
	input  *consoleInput
	output io.Writer
}

func openManagementConsole(ctx context.Context) (*managementConsole, error) {
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
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	opened := false
	defer func() {
		if !opened {
			<-managementConsoleGate
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := input.SyscallConn()
	if err != nil {
		return nil, err
	}
	var console *consoleInput
	var openErr error
	if err := raw.Control(func(fd uintptr) { console, openErr = openConsoleInput(fd, false, output) }); err != nil {
		return nil, err
	}
	if openErr != nil {
		return nil, openErr
	}
	opened = true
	return &managementConsole{input: console, output: output}, nil
}

func (this *managementConsole) close(err error) error {
	defer func() { <-managementConsoleGate }()
	return errors.Join(err, this.input.close(err != nil))
}

func (this *managementConsole) readLine(ctx context.Context, prompt string, echo bool) (line []byte, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	this.input.echo = echo
	defer func() {
		if !echo || resultErr != nil {
			resultErr = errors.Join(resultErr, writeConsoleText(this.output, "\n"))
		}
		if resultErr != nil {
			clear(line)
			line = nil
		}
	}()
	if err := writeConsoleText(this.output, prompt); err != nil {
		return nil, err
	}
	return this.input.readLine(ctx)
}

func writeConsoleText(output io.Writer, text string) error {
	written, err := io.WriteString(output, text)
	if err == nil && written != len(text) {
		return io.ErrShortWrite
	}
	return err
}

func keyboardInteractive(ctx context.Context, _ string, instructions string, questions []string, echos []bool) (answers []string, resultErr error) {
	console, err := openManagementConsole(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = console.close(resultErr)
		if resultErr != nil {
			clear(answers)
			answers = nil
		}
	}()
	if instructions != "" {
		if err := writeConsoleText(console.output, instructions+"\n"); err != nil {
			return nil, err
		}
	}
	answers = make([]string, 0, len(questions))
	for index, question := range questions {
		echo := index >= len(echos) || echos[index]
		line, err := console.readLine(ctx, question, echo)
		if err != nil {
			return answers, err
		}
		answers = append(answers, string(line))
		clear(line)
	}
	return answers, nil
}
