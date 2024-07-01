package pam

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lpam -fPIC

#include <security/pam_appl.h>
*/
import "C"

func NewHandle(native *C.pam_handle_t) *Handle {
	return &Handle{
		native,
	}
}

type Handle struct {
	native *C.pam_handle_t
}
