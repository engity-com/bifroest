package pam

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lpam -fPIC

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
*/
import "C"
import (
	"unsafe"
)

func (this *Handle) GetUser(prompt string) (string, *Error) {
	var cUser *C.char

	var getResult Result
	if len(prompt) > 0 {
		cPrompt := C.CString(prompt)
		defer C.free(unsafe.Pointer(cPrompt))
		getResult = Result(C.pam_get_user(this.native, cUser, cPrompt))
	} else {
		getResult = Result(C.pam_get_user(this.native, cUser, nil))
	}

	if !getResult.IsSuccess() {
		return "", getResult.Errorf(ErrorCauseTypeSystem, "failed to get user")
	}

	return C.GoString(cUser), nil
}
