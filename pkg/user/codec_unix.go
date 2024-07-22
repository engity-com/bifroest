//go:build unix && !android

package user

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/engity-com/bifroest/pkg/sys"
	"io"
)

var (
	errEmptyUserName    = errors.New("empty user name")
	errTooLongUserName  = errors.New("user name is longer than 32 characters")
	errIllegalUserName  = errors.New("illegal user name")
	errEmptyGroupName   = errors.New("empty group name")
	errTooLongGroupName = errors.New("group name is longer than 32 characters")
	errIllegalGroupName = errors.New("illegal group name")
	errTooLongGeocs     = errors.New("geocs is longer than 255 characters")
	errIllegalGeocs     = errors.New("illegal geocs")
)

type codecElementP[T any] interface {
	*T
	setLine(line [][]byte, allowBadName bool) error
}

type codecElementDecoder[T any, PT codecElementP[T]] func(fn string, r io.Reader, allowBadName bool, consumer codecConsumer[PT]) error

func decodeColonLinesFromFile[T any, PT codecElementP[T]](fn string, allowBadName bool, consumer codecConsumer[PT], decoder codecElementDecoder[T, PT]) (rErr error) {
	f, err := sys.OpenAndLockFileForRead(fn)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", fn, err)
	}
	defer func() {
		if err := f.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()

	return decoder(fn, f, allowBadName, consumer)
}

func decodeColonLinesFromReader[T any, PT codecElementP[T]](fn string, r io.Reader, allowBadName bool, expectedAmountOfColumns int, consumer codecConsumer[PT]) (err error) {
	rd := bufio.NewScanner(r)
	rd.Split(bufio.ScanLines)

	var pv PT = new(T)

	var lineNum uint32
	for rd.Scan() {
		line := bytes.SplitN(rd.Bytes(), colonFileSeparator, expectedAmountOfColumns+1)
		if len(line) == 1 && len(bytes.TrimSpace(line[0])) == 0 {
			continue
		}
		var slErr error
		if len(line) != expectedAmountOfColumns {
			slErr = fmt.Errorf("illegal amount of columns; expected %d; but got: %d", expectedAmountOfColumns, len(line))
		} else {
			slErr = pv.setLine(line, allowBadName)
		}

		if err := consumer(pv, slErr); err == codecConsumeEnd {
			return nil
		} else if err != nil {
			return fmt.Errorf("cannot parse %s:%d: %w", fn, lineNum, err)
		}
		lineNum++
	}

	return nil
}

func validateUserName(in []byte, allowBad bool) error {
	if allowBad {
		return validateBadUnixUser(in, errEmptyUserName, errTooLongUserName, errIllegalUserName)
	}
	return validateUnixName(in, errEmptyUserName, errTooLongUserName, errIllegalUserName)
}

func validateGroupName(in []byte, allowBad bool) error {
	if allowBad {
		return validateBadUnixUser(in, errEmptyGroupName, errTooLongGroupName, errIllegalGroupName)
	}
	return validateUnixName(in, errEmptyGroupName, errTooLongGroupName, errIllegalGroupName)
}

func validateBadUnixUser(in []byte, errEmpty, errTooLong, errIllegal error) error {
	if len(in) == 0 {
		return errEmpty
	}
	if len(in) > 32 {
		return errTooLong
	}
	if len(in) == 1 && in[0] == '.' {
		return errIllegal
	}
	if len(in) == 2 && in[0] == '.' && in[1] == '.' {
		return errIllegal
	}
	for i, c := range in {
		if i == 0 && (c == '~' || c == '-' || c == '+') {
			return errIllegal
		}
		if c < 33 { // At least '!'
			return errIllegal
		}
		if c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' || c == '"' || c == '>' || c == '<' || c == '|' || c == ',' {
			return errIllegal
		}
	}
	return nil
}

func validateUnixName(in []byte, errEmpty, errTooLong, errIllegal error) error {
	lIn := len(in)
	if lIn == 0 {
		return errEmpty
	}
	if lIn > 32 {
		return errTooLong
	}
	if lIn == 1 && in[0] == '.' {
		return errIllegal
	}
	if lIn == 2 && in[0] == '.' && in[1] == '.' {
		return errIllegal
	}
	var containsAtLeastOneNonNumeric bool
	for i, c := range in {
		if c >= 'a' && c <= 'z' {
			containsAtLeastOneNonNumeric = true
			continue
		}
		if c >= 'A' && c <= 'Z' {
			containsAtLeastOneNonNumeric = true
			continue
		}
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '_' || c == '.' {
			containsAtLeastOneNonNumeric = true
			continue
		}
		if i > 0 && c == '-' {
			containsAtLeastOneNonNumeric = true
			continue
		}
		if i == lIn-1 && c == '$' {
			containsAtLeastOneNonNumeric = true
			continue
		}
		return errIllegal
	}
	if !containsAtLeastOneNonNumeric {
		return errIllegal
	}
	return nil
}

func validateGeocs(in []byte) error {
	if len(in) > 255 {
		return errTooLongGeocs
	}
	for _, c := range in {
		if c == 0 || c == ':' || c == '\n' {
			return errIllegalGeocs
		}
	}
	return nil
}

func validateColonFilePathColumn(in []byte, errEmpty, errTooLong, errIllegal error) error {
	if len(in) == 0 {
		return errEmpty
	}
	if len(in) > 255 {
		return errTooLong
	}
	for _, c := range in {
		if c == 0 || c == ':' || c == '\n' {
			return errIllegal
		}
	}
	return nil
}
