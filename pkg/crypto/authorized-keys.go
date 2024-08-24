package crypto

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

var (
	ErrIllegalSshKey               = errors.New("illegal ssh key found")
	ErrIllegalAuthorizedKeysFormat = errors.New("illegal authorized keys format")
)

const (
	maxAuthorizedKeysLineSize = 10 * 1024
)

type AuthorizedKeys string

func (this AuthorizedKeys) ForEach(consumer func(i int, key ssh.PublicKey, comment string, opts []AuthorizedKeyOption) (canContinue bool, err error)) error {
	if len(this) == 0 {
		return nil
	}

	return parseAuthorizedKeys(bytes.NewReader([]byte(this)), consumer)
}

func (this AuthorizedKeys) Get() ([]AuthorizedKeyWithOptions, error) {
	return getAuthorizedKeysOf(this)
}

func (this AuthorizedKeys) Validate() error {
	return validateAuthorizedKeysOf(this)
}

func (this AuthorizedKeys) IsZero() bool {
	return strings.TrimSpace(string(this)) == ""
}

func (this *AuthorizedKeys) Trim() error {
	*this = AuthorizedKeys(strings.TrimSpace(string(*this)))
	return nil
}

func (this AuthorizedKeys) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuthorizedKeys:
		return this.isEqualTo(&v)
	case *AuthorizedKeys:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizedKeys) isEqualTo(other *AuthorizedKeys) bool {
	return this == *other
}

type getAuthorizedKeysOfSource interface {
	IsZero() bool
	ForEach(func(int, ssh.PublicKey, string, []AuthorizedKeyOption) (bool, error)) error
}

func getAuthorizedKeysOf(source getAuthorizedKeysOfSource) ([]AuthorizedKeyWithOptions, error) {
	var result []AuthorizedKeyWithOptions
	return result, source.ForEach(func(i int, key ssh.PublicKey, comment string, opts []AuthorizedKeyOption) (bool, error) {
		result = append(result, AuthorizedKeyWithOptions{key, opts})
		return true, nil
	})
}

func validateAuthorizedKeysOf(source getAuthorizedKeysOfSource) error {
	if source.IsZero() {
		return nil
	}

	atLeastOne := false
	if err := source.ForEach(func(int, ssh.PublicKey, string, []AuthorizedKeyOption) (canContinue bool, err error) {
		atLeastOne = true
		return false, nil
	}); err != nil {
		return err
	}
	if !atLeastOne {
		return fmt.Errorf("illegal or non-existent authorized keys: %v", source)
	}
	return nil
}

func parseAuthorizedKeys(r io.Reader, consumer func(i int, key ssh.PublicKey, comment string, options []AuthorizedKeyOption) (canContinue bool, err error)) error {
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	scanner.Buffer(make([]byte, maxAuthorizedKeysLineSize), maxAuthorizedKeysLineSize)

	var i int
	for scanner.Scan() {
		line := scanner.Bytes()
		pub, comment, options, err := parseAuthorizedKey(line)
		if err != nil {
			return err
		}
		if pub == nil {
			continue
		}
		canContinue, err := consumer(i, pub, comment, options)
		if err != nil || !canContinue {
			return err
		}
		i++
	}
	return scanner.Err()
}

func parseAuthorizedKey(line []byte) (out ssh.PublicKey, comment string, options []AuthorizedKeyOption, err error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] == '#' {
		return nil, "", nil, nil
	}

	var algo string
	algo, line = cutOffSshKeyAlgo(line)
	if algo == "" {
		// No key type recognized. Maybe there's an options field at the beginning.
		var b byte
		inQuote := false
		optionStart := 0
		var i int
		for i, b = range line {
			isEnd := !inQuote && (b == ' ' || b == '\t')
			if (b == ',' && !inQuote) || isEnd {
				if i-optionStart > 0 {
					var option AuthorizedKeyOption
					if err := option.UnmarshalText(line[optionStart:i]); err != nil {
						return nil, "", nil, fmt.Errorf("%w: %v", ErrIllegalAuthorizedKeysFormat, err)
					}
					options = append(options, option)
				}
				optionStart = i + 1
			}
			if isEnd {
				break
			}
			if b == '"' && (i == 0 || (i > 0 && line[i-1] != '\\')) {
				inQuote = !inQuote
			}
		}
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i == len(line) {
			return nil, "", nil, ErrIllegalAuthorizedKeysFormat
		}
		algo, line = cutOffSshKeyAlgo(line[i:])
	}
	if algo == "" {
		return nil, "", nil, ErrIllegalAuthorizedKeysFormat
	}

	i := bytes.IndexAny(line, " \t")
	var base64Key []byte
	if i == -1 {
		base64Key = bytes.TrimSpace(line)
	} else {
		base64Key, comment = bytes.TrimSpace(line[:i]), strings.TrimSpace(string(line[i+1:]))
	}

	key := make([]byte, base64.StdEncoding.DecodedLen(len(base64Key)))
	n, err := base64.StdEncoding.Decode(key, base64Key)
	if err != nil {
		return nil, "", nil, fmt.Errorf("%w: %v", ErrIllegalSshKey, err)
	}
	key = key[:n]
	out, err = ssh.ParsePublicKey(key)
	if err != nil {
		return nil, "", nil, fmt.Errorf("%w: %v", ErrIllegalSshKey, err)
	}

	return out, comment, options, nil
}

func getSshKeyAlgo(in []byte) string {
	switch string(in) {
	case ssh.KeyAlgoRSA:
		return string(in)
	case ssh.KeyAlgoDSA:
		return string(in)
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return string(in)
	case ssh.KeyAlgoSKECDSA256:
		return string(in)
	case ssh.KeyAlgoED25519:
		return string(in)
	case ssh.KeyAlgoSKED25519:
		return string(in)
	default:
		return ""
	}
}

func cutOffSshKeyAlgo(in []byte) (string, []byte) {
	i := bytes.IndexAny(in, " \t")
	if i == -1 {
		return "", in
	}
	algo := getSshKeyAlgo(in[:i])
	if algo == "" {
		return "", in
	}
	return algo, in[i+1:]
}
