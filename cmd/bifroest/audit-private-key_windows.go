//go:build windows

package main

import goos "os"

func validateAuditPrivateKeyPermissions(_ string, _ goos.FileInfo) error {
	return nil
}
