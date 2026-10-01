//go:build darwin

package protocol

import (
	"encoding/binary"
	"fmt"

	"github.com/shirou/gopsutil/v4/process"
)

func processEnviron(candidate *process.Process) ([]string, error) {
	raw, err := readDarwinProcessArguments(int(candidate.Pid))
	if err != nil {
		return nil, err
	}
	return parseDarwinProcessEnvironment(raw)
}

func parseDarwinProcessEnvironment(raw []byte) ([]string, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("process arguments are shorter than the argc header")
	}
	argc := int(int32(binary.LittleEndian.Uint32(raw[:4])))
	if argc < 0 || argc > len(raw) {
		return nil, fmt.Errorf("invalid process argument count %d", argc)
	}
	cursor := 4
	_, cursor, err := darwinProcessCString(raw, cursor)
	if err != nil {
		return nil, fmt.Errorf("invalid executable path: %w", err)
	}
	for cursor < len(raw) && raw[cursor] == 0 {
		cursor++
	}
	for index := 0; index < argc; index++ {
		_, cursor, err = darwinProcessCString(raw, cursor)
		if err != nil {
			return nil, fmt.Errorf("invalid process argument %d: %w", index, err)
		}
	}

	result := make([]string, 0)
	for cursor < len(raw) {
		for cursor < len(raw) && raw[cursor] == 0 {
			cursor++
		}
		if cursor == len(raw) {
			break
		}
		var value string
		value, cursor, err = darwinProcessCString(raw, cursor)
		if err != nil {
			return nil, fmt.Errorf("invalid process environment: %w", err)
		}
		result = append(result, value)
	}
	return result, nil
}

func darwinProcessCString(raw []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(raw) {
		return "", offset, fmt.Errorf("missing NUL-terminated value")
	}
	for index := offset; index < len(raw); index++ {
		if raw[index] == 0 {
			return string(raw[offset:index]), index + 1, nil
		}
	}
	return "", offset, fmt.Errorf("unterminated value")
}
