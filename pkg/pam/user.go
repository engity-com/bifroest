package pam

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lpam -fPIC

#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
*/
import "C"
import (
	"unsafe"
)

func (this *Handle) GetUser(prompt string) (string, error) {
	var cUser *C.char

	var getResult Result
	if len(prompt) > 0 {
		cPrompt := C.CString(prompt)
		defer C.free(unsafe.Pointer(cPrompt))
		getResult = Result(C.pam_get_user(this.native, &cUser, cPrompt))
	} else {
		getResult = Result(C.pam_get_user(this.native, &cUser, nil))
	}

	if !getResult.IsSuccess() {
		return "", getResult.Errorf(ErrorCauseTypeSystem, "failed to get user")
	}

	return C.GoString(cUser), nil
}

func (this *Handle) SetUser(name string) error {
	cName := unsafe.Pointer(C.CString(name))
	defer C.free(cName)

	res := Result(C.pam_set_item(this.native, C.int(ItemTypeUsername), cName))

	if !res.IsSuccess() {
		return res.Errorf(ErrorCauseTypeSystem, "failed to set user")
	}

	return nil
}
