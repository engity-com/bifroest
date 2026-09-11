//go:build unix

package crypto

import "os"

func readPrivateKeyFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
