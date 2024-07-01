//go:build unix

package user

import (
	"errors"
	"strconv"
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
