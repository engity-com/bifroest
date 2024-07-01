//go:build cgo && linux && !without_yescrypt

package password

/*
#cgo LDFLAGS: -lcrypt
#include <stdlib.h>
#include <crypt.h>
*/
import "C"
import "unsafe"

func init() {
	instance := &Yescrypt{}
	Instances["$y$"] = instance
}

type Yescrypt struct{}

func (p *Yescrypt) Validate(password string, hash []byte) (bool, error) {
	cKey := C.CString(password)
	defer C.free(unsafe.Pointer(cKey))
	cHash := C.CString(string(hash))
	defer C.free(unsafe.Pointer(cHash))

	out := C.crypt(cKey, cHash)

	return C.GoString(out) == string(hash), nil
}
