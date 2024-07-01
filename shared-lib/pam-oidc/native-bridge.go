package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lpam -fPIC

#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

int pamSmAuthenticateS(pam_handle_t *pamh, int flags, int argc, char **argv);

__attribute__((weak))
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return pamSmAuthenticateS(pamh, flags, argc, (char**)argv);
}

int pamSmSetcredS(pam_handle_t *pamh, int flags, int argc, char **argv);

__attribute__((weak))
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return pamSmSetcredS(pamh, flags, argc, (char**)argv);
}
*/
import "C"

import (
	"github.com/engity/pam-oidc/pkg/native"
	"github.com/engity/pam-oidc/pkg/pam"
	"unsafe"
)

//export pamSmAuthenticateS
func pamSmAuthenticateS(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	handle := pam.NewHandle(unsafe.Pointer(pamh))
	pfs := pam.FlagsFromBitMask(uint64(flags))
	args := native.ParseCArgv(int(argc), unsafe.Pointer(argv))

	return C.int(pamSmAuthenticate(handle, pfs, args...))
}

//export pamSmSetcredS
func pamSmSetcredS(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	handle := pam.NewHandle(unsafe.Pointer(pamh))
	pfs := pam.FlagsFromBitMask(uint64(flags))
	args := native.ParseCArgv(int(argc), unsafe.Pointer(argv))

	return C.int(pamSmSetcred(handle, pfs, args...))
}
