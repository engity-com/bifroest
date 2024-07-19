package user

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
)

var (
	codecConsumeEnd = errors.New("consume end")

	colonFileSeparator = []byte(":")
)

type codecConsumer[T any] func(T) error

func parseColonFile(fn string, r io.Reader, expectedAmountOfColumns int, consumer func(line [][]byte) error) (err error) {
	rd := bufio.NewScanner(r)
	rd.Split(bufio.ScanLines)

	var lineNum uint32
	for rd.Scan() {
		line := bytes.SplitN(rd.Bytes(), colonFileSeparator, expectedAmountOfColumns+1)
		if len(line) != expectedAmountOfColumns {
			continue
		}
		if err := consumer(line); err == codecConsumeEnd {
			return nil
		} else if err != nil {
			return fmt.Errorf("cannot parse %s:%d: %w", fn, lineNum, err)
		}
		lineNum++
	}

	return nil
}

func parseUint32Column(line [][]byte, columnIndex int, errEmpty, errIllegal error) (_ uint32, hasValue bool, _ error) {
	if len(line[columnIndex]) == 0 {
		if errEmpty != nil {
			return 0, false, errEmpty
		}
		return 0, false, nil
	}
	v, err := strconv.ParseUint(string(line[columnIndex]), 10, 32)
	if err != nil {
		return 0, false, errIllegal
	}
	return uint32(v), true, nil
}

func parseUint64Column(line [][]byte, columnIndex int, errEmpty, errIllegal error) (_ uint64, hasValue bool, _ error) {
	if len(line[columnIndex]) == 0 {
		if errEmpty != nil {
			return 0, false, errEmpty
		}
		return 0, false, nil
	}
	v, err := strconv.ParseUint(string(line[columnIndex]), 10, 32)
	if err != nil {
		return 0, false, errIllegal
	}
	return v, true, nil
}
