package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lpam -fPIC

#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

int pam_sm_authenticate_s(pam_handle_t *pamh, int flags, int argc, char **argv);

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return pam_sm_authenticate_s(pamh, flags, argc, (char**)argv);
}

int pam_sm_setcred_s(pam_handle_t *pamh, int flags, int argc, char **argv);

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, char **argv) {
  return pam_sm_setcred_s(pamh, flags, argc, (char**)argv);
}
*/
import "C"

import (
	"github.com/engity/pam-oidc/pkg/native"
	"github.com/engity/pam-oidc/pkg/pam"
)

//export pam_sm_authenticate_s
func pamSmAuthenticateS(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	handle := pam.NewHandle(pamh)
	pfs := pam.FlagsFromBitMask(uint64(flags))

	return C.int(pamSmAuthenticate(handle, pfs, native.ParseCArgv(argc, argv)...))
}

//export pam_sm_setcred_s
func pamSmSetcredS(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	handle := pam.NewHandle(pamh)
	pfs := pam.FlagsFromBitMask(uint64(flags))

	return C.int(pamSmSetcred(handle, pfs, native.ParseCArgv(argc, argv)...))
}
