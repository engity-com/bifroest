//go:build darwin

package user

import (
	osuser "os/user"
	"runtime"
	"testing"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// A read-only ABI/policy observation, not a PasswordAccountPolicyChecker. It
// never binds authentication, password-change, record-write or credential APIs.
// Opaque password metadata is deliberately NOT treated as a nonempty password.
func TestDarwinOpenDirectoryReadOnlyPolicyAPI(t *testing.T) {
	current, err := osuser.Current()
	require.NoError(t, err)
	cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_LOCAL)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, purego.Dlclose(cf)) })
	od, err := purego.Dlopen("/System/Library/Frameworks/OpenDirectory.framework/OpenDirectory", purego.RTLD_NOW|purego.RTLD_LOCAL)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, purego.Dlclose(od)) })
	var release func(uintptr)
	var typeID func(uintptr) uintptr
	var stringTypeID, arrayTypeID func() uintptr
	var stringCreate func(uintptr, string, uint32) uintptr
	var stringLength func(uintptr) int64
	var stringRead func(uintptr, *byte, int64, uint32) bool
	var arrayCreate func(uintptr, *uintptr, int64, uintptr) uintptr
	var arrayCount func(uintptr) int64
	var arrayValue func(uintptr, int64) uintptr
	var errorCode func(uintptr) int64
	var sessionCreate func(uintptr, uintptr, *uintptr) uintptr
	var nodeCreate func(uintptr, uintptr, uintptr, *uintptr) uintptr
	var recordCopy func(uintptr, uintptr, uintptr, uintptr, *uintptr) uintptr
	var recordName func(uintptr) uintptr
	var valuesCopy func(uintptr, uintptr, *uintptr) uintptr
	var synchronize, authenticationAllowed func(uintptr, *uintptr) bool
	for _, binding := range []struct {
		library uintptr
		name    string
		target  any
	}{
		{cf, "CFRelease", &release}, {cf, "CFGetTypeID", &typeID},
		{cf, "CFStringGetTypeID", &stringTypeID}, {cf, "CFArrayGetTypeID", &arrayTypeID},
		{cf, "CFStringCreateWithCString", &stringCreate}, {cf, "CFStringGetLength", &stringLength}, {cf, "CFStringGetCString", &stringRead},
		{cf, "CFArrayCreate", &arrayCreate}, {cf, "CFArrayGetCount", &arrayCount}, {cf, "CFArrayGetValueAtIndex", &arrayValue}, {cf, "CFErrorGetCode", &errorCode},
		{od, "ODSessionCreate", &sessionCreate}, {od, "ODNodeCreateWithName", &nodeCreate},
		{od, "ODNodeCopyRecord", &recordCopy}, {od, "ODRecordGetRecordName", &recordName}, {od, "ODRecordCopyValues", &valuesCopy},
		{od, "ODRecordSynchronize", &synchronize}, {od, "ODRecordAuthenticationAllowed", &authenticationAllowed},
	} {
		symbol, err := purego.Dlsym(binding.library, binding.name)
		require.NoError(t, err)
		require.NotZero(t, symbol)
		purego.RegisterFunc(binding.target, symbol)
	}
	owned := func(reference uintptr) uintptr {
		require.NotZero(t, reference)
		t.Cleanup(func() { release(reference) })
		return reference
	}
	noError := func(operation string, reference uintptr) {
		if reference != 0 {
			code := errorCode(reference)
			release(reference)
			t.Fatalf("%s: native OpenDirectory error %d", operation, code)
		}
	}
	adopt := func(operation string, reference, nativeError uintptr) uintptr {
		if reference != 0 {
			t.Cleanup(func() { release(reference) })
		}
		noError(operation, nativeError)
		require.NotZero(t, reference)
		return reference
	}
	constant := func(name string) uintptr {
		symbol, err := purego.Dlsym(od, name)
		require.NoError(t, err)
		require.NotZero(t, symbol)
		reference := *(*uintptr)(unsafe.Pointer(symbol))
		require.NotZero(t, reference)
		require.Equal(t, stringTypeID(), typeID(reference))
		return reference
	}
	const utf8 = uint32(0x08000100)
	text := func(reference uintptr) string {
		require.NotZero(t, reference)
		require.Equal(t, stringTypeID(), typeID(reference))
		require.LessOrEqual(t, stringLength(reference), int64(256))
		var buffer [1025]byte
		require.True(t, stringRead(reference, &buffer[0], int64(len(buffer)), utf8))
		for i, value := range buffer {
			if value == 0 {
				return string(buffer[:i])
			}
		}
		t.Fatal("native identity string was not terminated")
		return ""
	}
	var nativeError uintptr
	session := sessionCreate(0, 0, &nativeError)
	session = adopt("session", session, nativeError)
	nodeName := owned(stringCreate(0, "/Local/Default", utf8))
	nativeError = 0
	node := nodeCreate(0, session, nodeName, &nativeError)
	node = adopt("local node", node, nativeError)
	name := owned(stringCreate(0, current.Username, utf8))
	uidAttribute, guidAttribute, passwordAttribute := constant("kODAttributeTypeUniqueID"), constant("kODAttributeTypeGUID"), constant("kODAttributeTypePassword")
	attributes := []uintptr{uidAttribute, guidAttribute}
	requested := owned(arrayCreate(0, &attributes[0], int64(len(attributes)), 0))
	runtime.KeepAlive(attributes)
	nativeError = 0
	record := recordCopy(node, constant("kODRecordTypeUsers"), name, requested, &nativeError)
	record = adopt("record", record, nativeError)
	// There are no record mutators in this binding table, so this cannot commit
	// pending writes. Synchronize explicitly refetches the two identity fields.
	nativeError = 0
	synced := synchronize(record, &nativeError)
	noError("synchronize", nativeError)
	require.True(t, synced)
	require.Equal(t, current.Username, text(recordName(record)))
	identityValue := func(attribute uintptr) string {
		var nativeError uintptr
		values := valuesCopy(record, attribute, &nativeError)
		if values != 0 {
			defer release(values)
		}
		noError("identity values", nativeError)
		require.NotZero(t, values)
		require.Equal(t, arrayTypeID(), typeID(values))
		require.EqualValues(t, 1, arrayCount(values))
		return text(arrayValue(values, 0))
	}
	require.Equal(t, current.Uid, identityValue(uidAttribute))
	guid, err := uuid.Parse(identityValue(guidAttribute))
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, guid)
	nativeError = 0
	allowed := authenticationAllowed(record, &nativeError)
	policyError := int64(0)
	if nativeError != 0 {
		policyError = errorCode(nativeError)
		release(nativeError)
	}
	if allowed {
		require.Zero(t, policyError, "native success with an error is not a valid policy decision")
	}
	require.True(t, allowed || policyError != 0, "a denied native policy needs an explicit native error, not inferred permission")
	passwordMetadata := "unavailable"
	nativeError = 0
	values := valuesCopy(record, passwordAttribute, &nativeError)
	if nativeError != 0 {
		release(nativeError)
		if values != 0 {
			release(values)
			values = 0
		}
	}
	if values != 0 {
		defer release(values)
		require.Equal(t, arrayTypeID(), typeID(values))
		if arrayCount(values) == 1 {
			value := arrayValue(values, 0)
			require.NotZero(t, value)
			if typeID(value) == stringTypeID() {
				passwordMetadata = "opaque-attribute"
				if stringLength(value) == 0 {
					passwordMetadata = "empty-attribute"
				}
			}
		}
	}
	// No password/hash value is copied into Go or written to test output.
	t.Logf("READONLY_OD_POLICY uid=%s guidValid=true allowed=%t nativeError=%d passwordMetadata=%s; observation only, no resume permission", current.Uid, allowed, policyError, passwordMetadata)
}
