//go:build darwin

package environment

import "os"

func configureLocalPtyDescriptors(*os.File, *os.File) error {
	return nil
}
