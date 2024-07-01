package pam

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lpam -fPIC

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
*/
import "C"
import "unsafe"

func NewHandle(native unsafe.Pointer) *Handle {
	return &Handle{
		native: (*C.pam_handle_t)(native),
	}
}

type Handle struct {
	native *C.pam_handle_t
}
