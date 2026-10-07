package managementclient

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

func readManagementPassword(prompt string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("SSH authentication needs a terminal or an SSH agent/usable identity file")
	}
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return nil, err
	}
	result, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	return result, err
}

func keyboardInteractive(_ string, instructions string, questions []string, echos []bool) ([]string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("SSH keyboard-interactive authentication needs a terminal")
	}
	if instructions != "" {
		if _, err := fmt.Fprintln(os.Stderr, instructions); err != nil {
			return nil, err
		}
	}
	answers := make([]string, 0, len(questions))
	input := bufio.NewReader(os.Stdin)
	for index, question := range questions {
		var answer string
		if index < len(echos) && !echos[index] {
			secret, err := readManagementPassword(question)
			if err != nil {
				return nil, err
			}
			answer = string(secret)
			for i := range secret {
				secret[i] = 0
			}
		} else {
			if _, err := fmt.Fprint(os.Stderr, question); err != nil {
				return nil, err
			}
			line, err := input.ReadString('\n')
			if err != nil {
				return nil, err
			}
			answer = strings.TrimRight(line, "\r\n")
		}
		answers = append(answers, answer)
	}
	return answers, nil
}
