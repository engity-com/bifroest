//go:build !unix

package crypto

import "os"

func validateServicePrivateKeyFile(path string, file *os.File, info os.FileInfo) error {
	return validateSecurePrivateKeyFile(path, file, info)
}
