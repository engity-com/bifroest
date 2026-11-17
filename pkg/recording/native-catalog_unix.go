//go:build unix

package recording

import (
	"fmt"
	"os"
	"reflect"
)

func nativeCatalogFileChange(_ *os.File, info os.FileInfo) (any, error) {
	// The supported Unix Stat_t variants spell ctime differently. Ignore atime,
	// which our own verified reads can update. Unknown platforms fail closed.
	stat := reflect.ValueOf(info.Sys())
	if stat.Kind() == reflect.Pointer && !stat.IsNil() {
		stat = stat.Elem()
	}
	if stat.Kind() == reflect.Struct {
		for _, name := range []string{"Ctim", "Ctimespec"} {
			if value := stat.FieldByName(name); value.IsValid() && value.CanInterface() {
				return value.Interface(), nil
			}
		}
	}
	return nil, fmt.Errorf("recording catalog cannot obtain a file change stamp")
}
