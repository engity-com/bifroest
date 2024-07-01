package pam

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lpam -fPIC

#include <security/pam_appl.h>
#include <security/pam_ext.h>

void pam_syslog_s(pam_handle_t *pamh, int priority, const char *str) {
  pam_syslog(pamh, priority, "%s", str);
}

void pam_prompt_s(pam_handle_t *pamh, int style, const char *str) {
  pam_prompt(pamh, style, "%s", str);
}
*/
import "C"

import (
	"fmt"
	"log/syslog"
	"unsafe"
)

func (this *Handle) Syslogf(priority syslog.Priority, format string, args ...any) {
	cstr := C.CString(fmt.Sprintf(format, args...))
	defer C.free(unsafe.Pointer(cstr))

	C.pam_syslog_str(this.native, C.int(priority), cstr)
}

func (this *Handle) Promptf(style int, format string, args ...any) {
	cstr := C.CString(fmt.Sprintf(format, args...))
	defer C.free(unsafe.Pointer(cstr))

	C.pam_prompt_s(this.native, C.int(style), cstr)
}

func (this *Handle) Infof(format string, args ...any) {
	this.Promptf(C.PAM_TEXT_INFO, format, args...)
}

func (this *Handle) Errorf(format string, args ...any) {
	this.Promptf(C.PAM_ERROR_MSG, format, args...)
}
