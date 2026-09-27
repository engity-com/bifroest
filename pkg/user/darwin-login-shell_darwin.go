//go:build darwin && cgo

package user

/*
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int bifroest_get_login_shell(const char *name, char **shell) {
	long configured_size = sysconf(_SC_GETPW_R_SIZE_MAX);
	size_t size = configured_size > 0 ? (size_t) configured_size : 16384;

	for (;;) {
		char *buffer = malloc(size);
		if (buffer == NULL) {
			return ENOMEM;
		}

		struct passwd entry;
		struct passwd *result = NULL;
		int err = getpwnam_r(name, &entry, buffer, size, &result);
		if (err == ERANGE) {
			free(buffer);
			if (size > (1U << 20)) {
				return ERANGE;
			}
			size *= 2;
			continue;
		}
		if (err != 0) {
			free(buffer);
			return err;
		}
		if (result == NULL) {
			free(buffer);
			return ENOENT;
		}

		*shell = strdup(entry.pw_shell == NULL ? "" : entry.pw_shell);
		free(buffer);
		return *shell == NULL ? ENOMEM : 0;
	}
}
*/
import "C"

import (
	"fmt"
	osuser "os/user"
	"unsafe"
)

func lookupDarwinLoginShell(name string) (string, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	var cShell *C.char
	code := C.bifroest_get_login_shell(cName, &cShell)
	if code == C.ENOENT {
		return "", osuser.UnknownUserError(name)
	}
	if code != 0 {
		return "", fmt.Errorf("getpwnam_r failed: %s", C.GoString(C.strerror(code)))
	}
	defer C.free(unsafe.Pointer(cShell))
	return C.GoString(cShell), nil
}
