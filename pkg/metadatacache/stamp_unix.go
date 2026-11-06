//go:build unix

package metadatacache

import (
	"fmt"
	"os"
	"reflect"
)

func identityAndChange(_ *os.File, info os.FileInfo) (string, error) {
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer && !value.IsNil() {
		value = value.Elem()
	}
	if value.Kind() == reflect.Struct {
		dev, ino := value.FieldByName("Dev"), value.FieldByName("Ino")
		for _, name := range []string{"Ctim", "Ctimespec"} {
			change := value.FieldByName(name)
			if dev.IsValid() && ino.IsValid() && change.IsValid() && dev.CanInterface() && ino.CanInterface() && change.CanInterface() {
				return fmt.Sprintf("%v/%v/%#v", dev.Interface(), ino.Interface(), change.Interface()), nil
			}
		}
	}
	return "", fmt.Errorf("metadata source identity/change stamp unavailable")
}
