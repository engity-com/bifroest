//go:build windows

package windowslocal

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Local-only class 29 is described by System Informer's ntsam.h as two BOOLEANs.
// This is not a Microsoft API compatibility guarantee. Query no password/hash/
// private/all-information class, and never infer support from an error or zero.
func observeSAMLocalLogonUI(ctx context.Context, account Account) (*observedSAMLogonUI, error) {
	if ctx == nil {
		return nil, fmt.Errorf("missing SAM logon-UI observation context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	separator := strings.LastIndexByte(account.SID, '-')
	if separator < 0 {
		return nil, fmt.Errorf("invalid local SAM observation selector")
	}
	domainSID, err := windows.StringToSid(account.SID[:separator])
	if err != nil {
		return nil, err
	}
	sid, err := windows.StringToSid(account.SID)
	if err != nil || sid.SubAuthorityCount() == 0 {
		return nil, fmt.Errorf("invalid SAM observation RID")
	}
	rid := sid.SubAuthority(uint32(sid.SubAuthorityCount() - 1))
	library := windows.NewLazySystemDLL("samlib.dll")
	connect, openDomain, openUser, query, closeHandle, free := library.NewProc("SamConnect"), library.NewProc("SamOpenDomain"), library.NewProc("SamOpenUser"), library.NewProc("SamQueryInformationUser"), library.NewProc("SamCloseHandle"), library.NewProc("SamFreeMemory")
	for _, procedure := range []*windows.LazyProc{connect, openDomain, openUser, query, closeHandle, free} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := procedure.Find(); err != nil {
			return nil, err
		}
	}
	check := func(operation string, status uintptr) error {
		if status != 0 {
			return fmt.Errorf("%s: NTSTATUS 0x%08x", operation, uint32(status))
		}
		return nil
	}
	type objectAttributes struct {
		Length                          uint32
		Root                            windows.Handle
		Name                            uintptr
		Attributes                      uint32
		SecurityDescriptor, SecurityQoS uintptr
	}
	return observeSAMLogonUIFlow(ctx, samLogonUIOperations{
		identity: func() error { _, err := currentAccount(account); return err },
		connect: func() (uintptr, error) {
			attributes := objectAttributes{}
			attributes.Length = uint32(unsafe.Sizeof(attributes))
			var handle windows.Handle
			status, _, _ := connect.Call(0, uintptr(unsafe.Pointer(&handle)), 0x21, uintptr(unsafe.Pointer(&attributes))) // local CONNECT | LOOKUP_DOMAIN only.
			return uintptr(handle), check("SamConnect", status)
		},
		openDomain: func(server uintptr) (uintptr, error) {
			var handle windows.Handle
			status, _, _ := openDomain.Call(server, 0x200, uintptr(unsafe.Pointer(domainSID)), uintptr(unsafe.Pointer(&handle))) // DOMAIN_LOOKUP only.
			runtime.KeepAlive(domainSID)
			return uintptr(handle), check("SamOpenDomain", status)
		},
		openUser: func(domain uintptr) (uintptr, error) {
			var handle windows.Handle
			status, _, _ := openUser.Call(domain, 0x19, uintptr(rid), uintptr(unsafe.Pointer(&handle))) // USER_READ_GENERAL | READ_LOGON | READ_ACCOUNT; no writes/password rights.
			return uintptr(handle), check("SamOpenUser", status)
		},
		query: func(user uintptr) (*samLogonUIValue, error) {
			var value *samLogonUIValue
			status, _, _ := query.Call(user, 29, uintptr(unsafe.Pointer(&value))) // ONLY local UserLogonUIInformation, no internal/all-information class.
			return value, check("SamQueryInformationUser logon-UI", status)
		},
		free: func(value *samLogonUIValue) error {
			status, _, _ := free.Call(uintptr(unsafe.Pointer(value)))
			return check("SamFreeMemory logon-UI", status)
		},
		close: func(handle uintptr) error {
			status, _, _ := closeHandle.Call(handle)
			return check("SamCloseHandle", status)
		},
	})
}
