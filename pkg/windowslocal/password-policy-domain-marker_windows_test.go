//go:build windows

package windowslocal

import (
	"crypto/rand"
	"encoding/hex"
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

type observedSAMDomainMarker struct {
	Modified uint64 `json:"modified"`
	Created  int64  `json:"created"`
}

// Research only: MS-SAMR documents DOMAIN_MODIFIED_INFORMATION as an NT4-
// replication update sequence. That alone does not establish local samlib ABI,
// coverage, stability on authentication, or suitability as a revocation epoch.
// Request only domain metadata, never user password/hash/private information.
func observeSAMDomainMarker(account Account) (marker observedSAMDomainMarker, resultErr error) {
	if _, err := currentAccount(account); err != nil {
		return marker, err
	}
	index := strings.LastIndexByte(account.SID, '-')
	if index < 0 {
		return marker, fmt.Errorf("invalid local account-domain selector")
	}
	domainSID, err := windows.StringToSid(account.SID[:index])
	if err != nil {
		return marker, err
	}
	library := windows.NewLazySystemDLL("samlib.dll")
	connect, open, query, closeHandle, free := library.NewProc("SamConnect"), library.NewProc("SamOpenDomain"), library.NewProc("SamQueryInformationDomain"), library.NewProc("SamCloseHandle"), library.NewProc("SamFreeMemory")
	for _, procedure := range []*windows.LazyProc{connect, open, query, closeHandle, free} {
		if err := procedure.Find(); err != nil {
			return marker, err
		}
	}
	check := func(operation string, status uintptr) error {
		if status != 0 {
			return fmt.Errorf("%s: NTSTATUS 0x%08x", operation, uint32(status))
		}
		return nil
	}
	defer func() {
		if resultErr != nil {
			marker = observedSAMDomainMarker{}
		}
	}()
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
	status, _, _ := connect.Call(0, uintptr(unsafe.Pointer(&server)), 0x21, uintptr(unsafe.Pointer(&attributes))) // CONNECT | LOOKUP_DOMAIN, local silo only.
	if server != 0 {
		defer func() {
			status, _, _ := closeHandle.Call(uintptr(server))
			resultErr = errors.Join(resultErr, check("SamCloseHandle server", status))
		}()
	}
	if err := check("SamConnect", status); err != nil {
		return marker, err
	}
	if server == 0 {
		return marker, fmt.Errorf("SamConnect returned no handle")
	}
	var domain windows.Handle
	status, _, _ = open.Call(uintptr(server), 4, uintptr(unsafe.Pointer(domainSID)), uintptr(unsafe.Pointer(&domain))) // DOMAIN_READ_OTHER_PARAMETERS only.
	runtime.KeepAlive(domainSID)
	if domain != 0 {
		defer func() {
			status, _, _ := closeHandle.Call(uintptr(domain))
			resultErr = errors.Join(resultErr, check("SamCloseHandle domain", status))
		}()
	}
	if err := check("SamOpenDomain", status); err != nil {
		return marker, err
	}
	if domain == 0 {
		return marker, fmt.Errorf("SamOpenDomain returned no handle")
	}
	var value *observedSAMDomainMarker
	status, _, _ = query.Call(uintptr(domain), 8, uintptr(unsafe.Pointer(&value))) // DomainModifiedInformation; no user/private query.
	if value != nil {
		defer func() {
			status, _, _ := free.Call(uintptr(unsafe.Pointer(value)))
			resultErr = errors.Join(resultErr, check("SamFreeMemory", status))
		}()
	}
	if err := check("SamQueryInformationDomain", status); err != nil {
		return marker, err
	}
	if value == nil {
		return marker, fmt.Errorf("SamQueryInformationDomain returned no domain metadata")
	}
	marker = *value
	if _, err := currentAccount(account); err != nil {
		return observedSAMDomainMarker{}, err
	}
	return marker, nil
}

func TestLocalSAMDomainChangeMarkerObservation(t *testing.T) {
	requireSAMPolicyContainer(t)
	account, password := newSAMPolicyAccount(t)
	before, err := observeSAMDomainMarker(account)
	if err != nil {
		t.Logf("SAM_DOMAIN_MARKER unavailable=%q; no capability or permission inferred", err)
		return
	}
	if before.Created <= 0 {
		t.Logf("SAM_DOMAIN_MARKER created=%d modified=%d; missing native domain identity, no capability", before.Created, before.Modified)
		return
	}
	accepted, err := ValidatePassword(account, password)
	require.NoError(t, err)
	require.True(t, accepted)
	afterPasswordLogon, err := observeSAMDomainMarker(account)
	require.NoError(t, err)
	token, err := s4uImpersonationTokenWithFlags(account.Name, s4uLogonFlagCheckLogonHours)
	require.NoError(t, err)
	require.NotZero(t, token)
	require.NoError(t, token.Close())
	afterS4U, err := observeSAMDomainMarker(account)
	require.NoError(t, err)
	var random [24]byte
	_, err = rand.Read(random[:])
	require.NoError(t, err)
	changedPassword := "R3set!" + hex.EncodeToString(random[:]) + "Z"
	units, err := windows.UTF16FromString(changedPassword)
	require.NoError(t, err)
	defer clear(units)
	pointer := &units[0]
	setSAMPolicyInfo(t, account, 1003, unsafe.Pointer(&pointer))
	afterReset, err := observeSAMDomainMarker(account)
	require.NoError(t, err)
	accepted, err = ValidatePassword(account, changedPassword)
	require.NoError(t, err)
	require.True(t, accepted, "the owned password reset must actually work")
	afterResetLogon, err := observeSAMDomainMarker(account)
	require.NoError(t, err)
	report := struct {
		Before, AfterPasswordLogon, AfterS4U, AfterReset, AfterResetLogon observedSAMDomainMarker
		StableOnAuthentication, ChangedOnPasswordReset                    bool
	}{before, afterPasswordLogon, afterS4U, afterReset, afterResetLogon, before == afterPasswordLogon && before == afterS4U && afterReset == afterResetLogon, afterReset.Created == before.Created && afterReset.Modified > before.Modified}
	raw, err := json.Marshal(report)
	require.NoError(t, err)
	t.Logf("SAM_DOMAIN_MARKER_OBSERVATION %s; research only, no eligibility", raw)
}
