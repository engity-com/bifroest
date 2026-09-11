//go:build windows

package crypto

import "golang.org/x/sys/windows"

func installPrivateKeyFile(temporary, target string) error {
	from, err := windowsPathPointer(temporary)
	if err != nil {
		return err
	}
	to, err := windowsPathPointer(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
