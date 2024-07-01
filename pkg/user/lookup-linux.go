package user

/*
#cgo solaris CFLAGS: -D_POSIX_PTHREAD_SEMANTICS
#cgo CFLAGS: -fno-stack-protector
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>

static struct passwd mygetpwnam_r(const char *name, char *buf, size_t buflen, int *found, int *perr) {
	struct passwd pwd;
	struct passwd *result;
	memset(&pwd, 0, sizeof(pwd));
	*perr = getpwnam_r(name, &pwd, buf, buflen, &result);
	*found = result != NULL;
	return pwd;
}

static struct group mygetgrgid_r(int gid, char *buf, size_t buflen, int *found, int *perr) {
	struct group grp;
	struct group *result;
	memset(&grp, 0, sizeof(grp));
	*perr = getgrgid_r(gid, &grp, buf, buflen, &result);
	*found = result != NULL;
	return grp;
}

static struct group mygetgrnam_r(const char *name, char *buf, size_t buflen, int *found, int *perr) {
	struct group grp;
	struct group *result;
	memset(&grp, 0, sizeof(grp));
	*perr = getgrnam_r(name, &grp, buf, buflen, &result);
	*found = result != NULL;
	return grp;
}

static struct passwd mygetpwuid_r(int uid, char *buf, size_t buflen, int *found, int *perr) {
	struct passwd pwd;
	struct passwd *result;
	memset (&pwd, 0, sizeof(pwd));
	*perr = getpwuid_r(uid, &pwd, buf, buflen, &result);
	*found = result != NULL;
	return pwd;
}

static int mygetgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) {
	return getgrouplist(user, group, groups, ngroups);
}
*/
import "C"
import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	userBuffer  = bufferKind(C._SC_GETPW_R_SIZE_MAX)
	groupBuffer = bufferKind(C._SC_GETGR_R_SIZE_MAX)
)

func Lookup(username string) (*User, error) {
	pwd, err := getStructPasswd(username)
	if err != nil {
		return nil, err
	}
	if pwd == nil {
		return nil, nil
	}

	result := User{
		Uid:         uint64(_C_pw_uid(pwd)),
		Gid:         uint64(_C_pw_gid(pwd)),
		Name:        _C_GoString(_C_pw_name(pwd)),
		DisplayName: _C_GoString(_C_pw_gecos(pwd)),
		Shell:       _C_GoString(_C_pw_shell(pwd)),
		HomeDir:     _C_GoString(_C_pw_dir(pwd)),
	}

	return &result, nil
}

func LookupUid(uid uint64) (*User, error) {
	var pwd _C_struct_passwd
	var found bool

	err := retryWithBuffer(userBuffer, func(buf []byte) syscall.Errno {
		var errno syscall.Errno
		pwd, found, errno = _C_getpwuid_r(_C_uid_t(uid),
			(*_C_char)(unsafe.Pointer(&buf[0])), _C_size_t(len(buf)))
		return errno
	})
	if err != nil {
		return nil, fmt.Errorf("user: lookup userid %d: %v", uid, err)
	}
	if !found {
		return nil, nil
	}

	return &User{
		Uid:         uint64(_C_pw_uid(&pwd)),
		Gid:         uint64(_C_pw_gid(&pwd)),
		Name:        _C_GoString(_C_pw_name(&pwd)),
		DisplayName: _C_GoString(_C_pw_gecos(&pwd)),
		Shell:       _C_GoString(_C_pw_shell(&pwd)),
		HomeDir:     _C_GoString(_C_pw_dir(&pwd)),
	}, nil
}

func getStructPasswd(username string) (*_C_struct_passwd, error) {
	var found bool
	var pwd _C_struct_passwd
	nameC := make([]byte, len(username)+1)
	copy(nameC, username)

	err := retryWithBuffer(userBuffer, func(buf []byte) syscall.Errno {
		var errno syscall.Errno
		pwd, found, errno = _C_getpwnam_r((*_C_char)(unsafe.Pointer(&nameC[0])), (*_C_char)(unsafe.Pointer(&buf[0])), _C_size_t(len(buf)))
		return errno
	})
	if err != nil {
		return nil, fmt.Errorf("cannot lookup user %q: %v", username, err)
	}
	if !found {
		return nil, nil
	}

	return &pwd, nil
}

const maxGroups = 2048

func (this *User) GetGids() ([]uint64, error) {
	userGID := _C_gid_t(this.Gid)
	loginC := make([]byte, len(this.Name)+1)
	copy(loginC, this.Name)

	n := _C_int(256)
	gidsC := make([]_C_gid_t, n)
	rv := C.mygetgrouplist((*_C_char)(unsafe.Pointer(&loginC[0])), userGID, &gidsC[0], &n)
	if rv == -1 {
		// Mac is the only Unix that does not set n properly when rv == -1, so
		// we need to use different logic for Mac vs. the other OS's.
		if err := groupRetry(this.Name, loginC, userGID, &gidsC, &n); err != nil {
			return nil, err
		}
	}
	gidsC = gidsC[:n]
	gids := make([]uint64, n)
	for i, g := range gidsC {
		gids[i] = uint64(g)
	}
	return gids, nil
}

// groupRetry retries getGroupList with much larger size for n. The result is
// stored in gids.
func groupRetry(username string, name []byte, userGID _C_gid_t, gids *[]_C_gid_t, n *_C_int) error {
	// More than initial buffer, but now n contains the correct size.
	if *n > maxGroups {
		return fmt.Errorf("user: %q is a member of more than %d groups", username, maxGroups)
	}
	*gids = make([]_C_gid_t, *n)
	rv := C.mygetgrouplist((*_C_char)(unsafe.Pointer(&name[0])), userGID, &(*gids)[0], n)
	if rv == -1 {
		return fmt.Errorf("user: list groups for %s failed", username)
	}
	return nil
}

const maxBufferSize = 1 << 20

func isSizeReasonable(sz int64) bool {
	return sz > 0 && sz <= maxBufferSize
}

// retryWithBuffer repeatedly calls f(), increasing the size of the
// buffer each time, until f succeeds, fails with a non-ERANGE error,
// or the buffer exceeds a reasonable limit.
func retryWithBuffer(kind bufferKind, f func([]byte) syscall.Errno) error {
	buf := make([]byte, kind.initialSize())
	for {
		errno := f(buf)
		if errno == 0 {
			return nil
		} else if runtime.GOOS == "aix" && errno+1 == 0 {
			// On AIX getpwuid_r appears to return -1,
			// not ERANGE, on buffer overflow.
		} else if errno != syscall.ERANGE {
			return errno
		}
		newSize := len(buf) * 2
		if !isSizeReasonable(int64(newSize)) {
			return fmt.Errorf("internal buffer exceeds %d bytes", maxBufferSize)
		}
		buf = make([]byte, newSize)
	}
}

func LookupGroup(name string) (*Group, error) {
	var grp _C_struct_group
	var found bool

	cname := make([]byte, len(name)+1)
	copy(cname, name)

	err := retryWithBuffer(groupBuffer, func(buf []byte) syscall.Errno {
		var errno syscall.Errno
		grp, found, errno = _C_getgrnam_r((*_C_char)(unsafe.Pointer(&cname[0])),
			(*_C_char)(unsafe.Pointer(&buf[0])), _C_size_t(len(buf)))
		return errno
	})
	if err != nil {
		return nil, fmt.Errorf("user: lookup groupname %s: %v", name, err)
	}
	if !found {
		return nil, nil
	}
	pGrp := &grp
	return &Group{
		Gid:  uint64(_C_gr_gid(pGrp)),
		Name: _C_GoString(_C_gr_name(pGrp)),
	}, nil
}

func LookupGid(gid uint64) (*Group, error) {
	var grp _C_struct_group
	var found bool

	err := retryWithBuffer(groupBuffer, func(buf []byte) syscall.Errno {
		var errno syscall.Errno
		grp, found, errno = _C_getgrgid_r(_C_gid_t(gid),
			(*_C_char)(unsafe.Pointer(&buf[0])), _C_size_t(len(buf)))
		return errno
	})
	if err != nil {
		return nil, fmt.Errorf("user: lookup groupid %d: %v", gid, err)
	}
	if !found {
		return nil, nil
	}
	pGrp := &grp
	return &Group{
		Gid:  uint64(_C_gr_gid(pGrp)),
		Name: _C_GoString(_C_gr_name(pGrp)),
	}, nil
}

type _C_char = C.char
type _C_int = C.int
type _C_gid_t = C.gid_t
type _C_uid_t = C.uid_t
type _C_size_t = C.size_t
type _C_struct_passwd = C.struct_passwd
type _C_struct_group = C.struct_group
type _C_long = C.long

func _C_sysconf(key _C_int) _C_long { return C.sysconf(key) }

func _C_pw_uid(p *_C_struct_passwd) _C_uid_t   { return p.pw_uid }
func _C_pw_gid(p *_C_struct_passwd) _C_gid_t   { return p.pw_gid }
func _C_pw_name(p *_C_struct_passwd) *_C_char  { return p.pw_name }
func _C_pw_gecos(p *_C_struct_passwd) *_C_char { return p.pw_gecos }
func _C_pw_dir(p *_C_struct_passwd) *_C_char   { return p.pw_dir }
func _C_pw_shell(p *_C_struct_passwd) *_C_char { return p.pw_shell }

func _C_gr_gid(g *_C_struct_group) _C_gid_t  { return g.gr_gid }
func _C_gr_name(g *_C_struct_group) *_C_char { return g.gr_name }

func _C_GoString(p *_C_char) string { return C.GoString(p) }

type bufferKind _C_int

func (k bufferKind) initialSize() _C_size_t {
	sz := _C_sysconf(_C_int(k))
	if sz == -1 {
		// DragonFly and FreeBSD do not have _SC_GETPW_R_SIZE_MAX.
		// Additionally, not all Linux systems have it, either. For
		// example, the musl libc returns -1.
		return 1024
	}
	if !isSizeReasonable(int64(sz)) {
		// Truncate.  If this truly isn't enough, retryWithBuffer will error on the first run.
		return maxBufferSize
	}
	return _C_size_t(sz)
}

func _C_getpwnam_r(name *_C_char, buf *_C_char, size _C_size_t) (pwd _C_struct_passwd, found bool, errno syscall.Errno) {
	var f, e _C_int
	pwd = C.mygetpwnam_r(name, buf, size, &f, &e)
	return pwd, f != 0, syscall.Errno(e)
}

func _C_getpwuid_r(uid _C_uid_t, buf *_C_char, size _C_size_t) (pwd _C_struct_passwd, found bool, errno syscall.Errno) {
	var f, e _C_int
	pwd = C.mygetpwuid_r(_C_int(uid), buf, size, &f, &e)
	return pwd, f != 0, syscall.Errno(e)
}

func _C_getgrnam_r(name *_C_char, buf *_C_char, size _C_size_t) (grp _C_struct_group, found bool, errno syscall.Errno) {
	var f, e _C_int
	grp = C.mygetgrnam_r(name, buf, size, &f, &e)
	return grp, f != 0, syscall.Errno(e)
}

func _C_getgrgid_r(gid _C_gid_t, buf *_C_char, size _C_size_t) (grp _C_struct_group, found bool, errno syscall.Errno) {
	var f, e _C_int
	grp = C.mygetgrgid_r(_C_int(gid), buf, size, &f, &e)
	return grp, f != 0, syscall.Errno(e)
}
