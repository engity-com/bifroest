//go:build windows

package crypto

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func readPrivateKeyFile(path string) ([]byte, error) {
	return readPrivateKeyFileUsing(path, os.ReadFile, time.Sleep)
}

func readPrivateKeyFileUsing(path string, read func(string) ([]byte, error), sleep func(time.Duration)) ([]byte, error) {
	const (
		attempts     = 100
		initialDelay = time.Millisecond
		maximumDelay = 50 * time.Millisecond
	)
	delay := initialDelay
	for attempt := range attempts {
		raw, err := read(path)
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return raw, err
		}
		if attempt == attempts-1 {
			return nil, err
		}
		sleep(delay)
		delay = min(delay*2, maximumDelay)
	}
	panic("unreachable")
}
