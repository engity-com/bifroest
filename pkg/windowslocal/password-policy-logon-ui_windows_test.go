//go:build windows

package windowslocal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

type observedSAMLogonUI struct {
	PasswordIsBlank bool `json:"passwordIsBlank"`
	AccountDisabled bool `json:"accountDisabled"`
}

// Research only. System Informer's ntsam.h describes local-only class 29 as two
// BOOLEANs, PasswordIsBlank and AccountIsDisabled. That is not a Microsoft API
// compatibility guarantee. Query no password/hash/private/all-information class,
// and infer no capability from an unsupported export/class or a zero value.
func observeSAMLocalLogonUI(ctx context.Context, account Account) (result *observedSAMLogonUI, resultErr error) {
	if ctx == nil {
		return nil, fmt.Errorf("missing SAM logon-UI observation context")
	}
	defer func() {
		resultErr = errors.Join(resultErr, ctx.Err())
		if resultErr != nil {
			result = nil
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := currentAccount(account); err != nil {
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
	attributes := objectAttributes{}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var server windows.Handle
	status, _, _ := connect.Call(0, uintptr(unsafe.Pointer(&server)), 0x21, uintptr(unsafe.Pointer(&attributes))) // local CONNECT | LOOKUP_DOMAIN only.
	if server != 0 {
		defer func() {
			status, _, _ := closeHandle.Call(uintptr(server))
			resultErr = errors.Join(resultErr, check("SamCloseHandle server", status))
		}()
	}
	if err := check("SamConnect", status); err != nil {
		return nil, err
	}
	if server == 0 {
		return nil, fmt.Errorf("SamConnect returned no handle")
	}
	var domain windows.Handle
	status, _, _ = openDomain.Call(uintptr(server), 0x200, uintptr(unsafe.Pointer(domainSID)), uintptr(unsafe.Pointer(&domain))) // DOMAIN_LOOKUP only.
	runtime.KeepAlive(domainSID)
	if domain != 0 {
		defer func() {
			status, _, _ := closeHandle.Call(uintptr(domain))
			resultErr = errors.Join(resultErr, check("SamCloseHandle domain", status))
		}()
	}
	if err := check("SamOpenDomain", status); err != nil {
		return nil, err
	}
	if domain == 0 {
		return nil, fmt.Errorf("SamOpenDomain returned no handle")
	}
	var user windows.Handle
	status, _, _ = openUser.Call(uintptr(domain), 0x19, uintptr(rid), uintptr(unsafe.Pointer(&user))) // USER_READ_GENERAL | READ_LOGON | READ_ACCOUNT; no write or password rights.
	if user != 0 {
		defer func() {
			status, _, _ := closeHandle.Call(uintptr(user))
			resultErr = errors.Join(resultErr, check("SamCloseHandle user", status))
		}()
	}
	if err := check("SamOpenUser", status); err != nil {
		return nil, err
	}
	if user == 0 {
		return nil, fmt.Errorf("SamOpenUser returned no handle")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var value *struct{ PasswordIsBlank, AccountIsDisabled uint8 }
	status, _, _ = query.Call(uintptr(user), 29, uintptr(unsafe.Pointer(&value))) // ONLY UserLogonUIInformation, never an internal/all-information class.
	if value != nil {
		defer func() {
			status, _, _ := free.Call(uintptr(unsafe.Pointer(value)))
			resultErr = errors.Join(resultErr, check("SamFreeMemory logon-UI", status))
		}()
	}
	if err := check("SamQueryInformationUser logon-UI", status); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("SamQueryInformationUser returned no logon-UI data")
	}
	if value.PasswordIsBlank > 1 || value.AccountIsDisabled > 1 {
		return nil, fmt.Errorf("unsupported SAM logon-UI BOOLEAN layout")
	}
	result = &observedSAMLogonUI{PasswordIsBlank: value.PasswordIsBlank != 0, AccountDisabled: value.AccountIsDisabled != 0}
	if _, err := currentAccount(account); err != nil {
		return nil, err
	}
	return result, nil
}

func TestLocalSAMLogonUIBlankPasswordObservation(t *testing.T) {
	requireSAMPolicyContainer(t)
	for _, test := range []struct {
		name                          string
		blank, disabled, requiredFlag bool
	}{
		{name: "nonblank"},
		{name: "blank", blank: true},
		{name: "blank-required-flag", blank: true, requiredFlag: true},
		{name: "disabled-nonblank", disabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			account, password := newSAMPolicyAccountWithPassword(t, !test.blank)
			if test.disabled || test.requiredFlag {
				flags := uint32(0x201)
				if test.disabled {
					flags |= 0x2
				}
				setSAMPolicyInfo(t, account, 1008, unsafe.Pointer(&flags))
			}
			state, err := inspectPreliminaryPasswordAccount(t.Context(), account)
			require.NoError(t, err)
			require.Equal(t, test.disabled, state.Flags&0x2 != 0)
			if test.requiredFlag {
				require.Zero(t, state.Flags&0x20, "real blank fixture must remain blank even without PASSWORD_NOT_REQUIRED")
			}
			observed, err := observeSAMLocalLogonUI(t.Context(), account)
			if err != nil {
				t.Logf("SAM_LOGON_UI_OBSERVATION unavailable=%q; research only, no eligibility", err)
				return
			}
			require.NotNil(t, observed)
			raw, err := json.Marshal(observed)
			require.NoError(t, err)
			t.Logf("SAM_LOGON_UI_OBSERVATION %s; research only, no eligibility", raw)
			require.Equal(t, test.blank, observed.PasswordIsBlank, "read-only local bit must distinguish the actual controlled blank/nonblank passwords")
			require.Equal(t, test.disabled, observed.AccountDisabled, "independent native flag control must agree")
			if test.blank {
				require.True(t, password == "", "blank fixture creation must not introduce a password")
			} else {
				require.True(t, len(password) > 0, "nonblank fixture creation must assign a password")
			}
		})
	}
}
