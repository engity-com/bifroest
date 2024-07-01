package pam

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lpam -fPIC

#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>

void pam_syslog_s(pam_handle_t *pamh, int priority, const char *str) {
  pam_syslog(pamh, priority, "%s", str);
}

int pam_prompt_s(pam_handle_t *pamh, int style, char **response, const char *str) {
  return pam_prompt(pamh, style, response, "%s", str);
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

	C.pam_syslog_s(this.native, C.int(priority), cstr)
}

func (this *Handle) Promptf(style int, format string, args ...any) (string, error) {
	cstr := C.CString(fmt.Sprintf(format, args...))
	defer C.free(unsafe.Pointer(cstr))

	var cResponse *C.char

	if res := Result(C.pam_prompt_s(this.native, C.int(style), &cResponse, cstr)); !res.IsSuccess() {
		return "", res.ToError(ErrorCauseTypeSystem)
	}

	return C.GoString(cResponse), nil
}

func (this *Handle) Infof(format string, args ...any) error {
	_, result := this.Promptf(C.PAM_TEXT_INFO, format, args...)
	return result
}

func (this *Handle) UncheckedInfof(format string, args ...any) {
	this.DoUnchecked("infof", func() error {
		return this.Infof(format, args...)
	})
}

func (this *Handle) Errorf(format string, args ...any) error {
	_, result := this.Promptf(C.PAM_ERROR_MSG, format, args...)
	return result
}

func (this *Handle) UncheckedErrorf(format string, args ...any) {
	this.DoUnchecked("errorf", func() error {
		return this.Errorf(format, args...)
	})
}

func (this *Handle) DoUnchecked(description string, what func() error) {
	if err := what(); err != nil {
		this.Syslogf(syslog.LOG_ERR, "%s failed: %v", description, err)
	}
}
