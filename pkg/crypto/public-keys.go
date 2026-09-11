package crypto

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

var ErrIllegalPublicKeysFormat = errors.New("illegal public keys format")

type PublicKeys string

func (this PublicKeys) ForEach(consumer func(i int, key ssh.PublicKey, comment string) (canContinue bool, err error)) error {
	if this.IsZero() {
		return nil
	}
	return parsePublicKeys(bytes.NewReader([]byte(this)), consumer)
}

func (this PublicKeys) Get() ([]ssh.PublicKey, error) {
	return getPublicKeysOf(this)
}

func (this PublicKeys) Validate() error {
	return validatePublicKeysOf(this)
}

func (this PublicKeys) IsZero() bool {
	return strings.TrimSpace(string(this)) == ""
}

func (this *PublicKeys) Trim() error {
	*this = PublicKeys(strings.TrimSpace(string(*this)))
	return nil
}

func (this PublicKeys) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case PublicKeys:
		return this == v
	case *PublicKeys:
		return v != nil && this == *v
	default:
		return false
	}
}

type publicKeysSource interface {
	IsZero() bool
	ForEach(func(int, ssh.PublicKey, string) (bool, error)) error
}

func getPublicKeysOf(source publicKeysSource) ([]ssh.PublicKey, error) {
	var result []ssh.PublicKey
	err := source.ForEach(func(_ int, key ssh.PublicKey, _ string) (bool, error) {
		result = append(result, key)
		return true, nil
	})
	return result, err
}

func validatePublicKeysOf(source publicKeysSource) error {
	if source.IsZero() {
		return nil
	}
	found := false
	if err := source.ForEach(func(_ int, _ ssh.PublicKey, _ string) (bool, error) {
		found = true
		return true, nil
	}); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("illegal or non-existent public keys: %v", source)
	}
	return nil
}

func parsePublicKeys(r io.Reader, consumer func(i int, key ssh.PublicKey, comment string) (canContinue bool, err error)) error {
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	scanner.Buffer(make([]byte, maxAuthorizedKeysLineSize), maxAuthorizedKeysLineSize)

	var i int
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, comment, options, rest, err := ssh.ParseAuthorizedKey(line)
		if err != nil || key == nil || len(bytes.TrimSpace(rest)) != 0 || len(options) != 0 {
			if err == nil {
				err = ErrIllegalPublicKeysFormat
			}
			return fmt.Errorf("%w at entry #%d: %v", ErrIllegalPublicKeysFormat, i, err)
		}
		if _, isCertificate := key.(*ssh.Certificate); isCertificate {
			return fmt.Errorf("%w at entry #%d: certificates are not CA public keys", ErrIllegalPublicKeysFormat, i)
		}
		canContinue, err := consumer(i, key, comment)
		if err != nil || !canContinue {
			return err
		}
		i++
	}
	return scanner.Err()
}
