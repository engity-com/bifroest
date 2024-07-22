package user

import (
	"errors"
	"strconv"
)

var (
	codecConsumeEnd = errors.New("consume end")

	colonFileSeparator = []byte(":")
)

type codecConsumer[T any] func(T, error) error

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
