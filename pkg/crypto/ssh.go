package crypto

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/sys"
)

const maxAuthorizedKeysFileSize = 4 << 20

func DoWithEachAuthorizedKey[R any](requireExistence bool, callback func(ssh.PublicKey, []AuthorizedKeyOption) (result R, canContinue bool, err error), files ...string) (result R, err error) {
	return doWithEachAuthorizedKey(requireExistence, callback, os.Open, files...)
}

func doWithEachAuthorizedKey[R any](requireExistence bool, callback func(ssh.PublicKey, []AuthorizedKeyOption) (result R, canContinue bool, err error), open func(string) (*os.File, error), files ...string) (result R, err error) {
	fail := func(err error) (R, error) {
		var empty R
		return empty, err
	}
	failf := func(message string, args ...any) (R, error) {
		return fail(fmt.Errorf(message, args...))
	}

	for _, file := range files {
		f, err := open(file)
		if !requireExistence && sys.IsNotExist(err) {
			continue
		}
		if err != nil {
			return failf("failed to read authorized keys file %q: %v", file, err)
		}
		rest, readErr := readAuthorizedKeys(f)
		closeErr := f.Close()
		if readErr != nil {
			return failf("failed to read authorized keys file %q: %w", file, readErr)
		}
		if closeErr != nil {
			return failf("failed to close authorized keys file %q: %w", file, closeErr)
		}
		var entry int
		for len(rest) > 0 {
			var pub ssh.PublicKey
			var plainOptions []string
			pub, _, plainOptions, rest, err = ssh.ParseAuthorizedKey(rest)
			if err != nil {
				return failf("failed to parse entry #%d of authorized keys file %q: %v", entry, file, err)
			}
			options := make([]AuthorizedKeyOption, len(plainOptions))
			for i, plainOption := range plainOptions {
				if err := options[i].Set(plainOption); err != nil {
					return failf("failed to parse option #%d of entry #%d of authorized keys file %q: %v", i, entry, file, err)
				}
			}
			var canContinue bool
			result, canContinue, err = callback(pub, options)
			if err != nil {
				return failf("failed to evaluate entry #%d of authorized keys file %q: %v", entry, file, err)
			}
			if !canContinue {
				return result, nil
			}
			entry++
		}
	}
	return result, nil
}

func readAuthorizedKeys(file *os.File) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("authorized keys must be a regular file")
	}
	if info.Size() > maxAuthorizedKeysFileSize {
		return nil, fmt.Errorf("authorized keys exceed %d bytes", maxAuthorizedKeysFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAuthorizedKeysFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAuthorizedKeysFileSize {
		return nil, fmt.Errorf("authorized keys exceed %d bytes", maxAuthorizedKeysFileSize)
	}
	return data, nil
}
