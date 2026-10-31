//go:build darwin && !without_pam

package authorization

import (
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/stretchr/testify/require"
)

// Unlike direct-handler models, these invoke the actual registered FFI callback
// with native allocated framing and deliberately ignore its error status in the
// simulated PAM API. No OS account/service/password authentication is performed.
func TestDarwinPamNativeConversationErrorsCannotBecomeSuccess(t *testing.T) {
	for _, primary := range []bool{false, true} {
		method := "account-only"
		if primary {
			method = "primary"
		}
		for _, fault := range []string{"oversized-native-message", "zero-count", "excess-count", "nil-messages", "nil-message", "nil-responses", "allocation-failure", "native-reader-panic"} {
			t.Run(method+"/"+fault, func(t *testing.T) { assertDarwinPamNativeCallbackFailure(t, primary, "operation", fault) })
		}
	}
	t.Run("start-callback", func(t *testing.T) {
		assertDarwinPamNativeCallbackFailure(t, false, "start", "oversized-native-message")
	})
	t.Run("end-callback-clears-result", func(t *testing.T) { assertDarwinPamNativeCallbackFailure(t, false, "end", "oversized-native-message") })
	t.Run("response-allocation-failure", func(t *testing.T) {
		assertDarwinPamNativeCallbackFailure(t, true, "operation", "response-allocation-failure")
	})
	for _, fault := range []string{"typed-handler-denial", "handler-panic", "second-message-handler-panic", "second-message-invalid-frame", "typed-handler-denial+end-error"} {
		t.Run(fault, func(t *testing.T) { assertDarwinPamNativeCallbackFailure(t, true, "operation", fault) })
	}
	t.Run("native-end-error", func(t *testing.T) { assertDarwinPamNativeCallbackFailure(t, false, "none", "none+end-error") })
	t.Run("native-end-and-callback-error", func(t *testing.T) {
		assertDarwinPamNativeCallbackFailure(t, false, "end", "oversized-native-message+end-error")
	})
	t.Run("prior-denial-and-new-end-callback-error", func(t *testing.T) {
		assertDarwinPamNativeCallbackFailure(t, true, "operation-and-end", "typed-handler-denial")
	})
}

func assertDarwinPamNativeCallbackFailure(t *testing.T, primary bool, phase, fault string) {
	t.Helper()
	endFailure := strings.HasSuffix(fault, "+end-error")
	fault = strings.TrimSuffix(fault, "+end-error")
	base, err := loadDarwinPam()
	require.NoError(t, err)
	allocate := func(size uintptr) uintptr {
		pointer := base.calloc(1, size)
		require.NotZero(t, pointer)
		t.Cleanup(func() { base.free(pointer) })
		return pointer
	}
	text := func(value string) uintptr {
		pointer := allocate(uintptr(len(value) + 1))
		copy(unsafe.Slice((*byte)(unsafe.Pointer(pointer)), len(value)+1), value)
		return pointer
	}
	messageText := "fixture message"
	if fault == "oversized-native-message" {
		messageText = strings.Repeat("x", darwinPamMaximumMessageSize+1)
	}
	style := darwinPamTextInfo
	if fault == "response-allocation-failure" || fault == "typed-handler-denial" || strings.Contains(fault, "handler-panic") || fault == "second-message-invalid-frame" {
		style = darwinPamPromptEchoOff
	}
	message := allocate(unsafe.Sizeof(darwinPamMessage{}))
	*(*darwinPamMessage)(unsafe.Pointer(message)) = darwinPamMessage{Style: style, Message: text(messageText)}
	messageCount := int32(1)
	if strings.HasPrefix(fault, "second-message-") {
		messageCount = 2
	}
	messages := allocate(uintptr(messageCount) * unsafe.Sizeof(uintptr(0)))
	*(*uintptr)(unsafe.Pointer(messages)) = message
	if messageCount == 2 {
		*(*uintptr)(unsafe.Pointer(messages + unsafe.Sizeof(uintptr(0)))) = message
	}
	if fault == "second-message-invalid-frame" {
		*(*uintptr)(unsafe.Pointer(messages + unsafe.Sizeof(uintptr(0)))) = 0
	}
	if fault == "nil-message" {
		*(*uintptr)(unsafe.Pointer(messages)) = 0
	}
	username := text("alice")
	api := *base
	api.pamStrerror = func(uintptr, int32) string { return "fixture native error" }
	type nativeAllocation struct {
		size     uintptr
		answer   bool
		freed    int
		scrubbed bool
	}
	tracked := map[uintptr]*nativeAllocation{}
	t.Cleanup(func() {
		for pointer, allocation := range tracked {
			if allocation.freed == 0 {
				base.free(pointer)
			}
		}
	})
	allocations := 0
	api.calloc = func(count, size uintptr) uintptr {
		allocations++
		if fault == "allocation-failure" || (fault == "response-allocation-failure" && allocations == 2) {
			return 0
		}
		pointer := base.calloc(count, size)
		if pointer != 0 {
			tracked[pointer] = &nativeAllocation{size: count * size, answer: size == 1}
		}
		return pointer
	}
	api.free = func(pointer uintptr) {
		if allocation := tracked[pointer]; allocation != nil {
			allocation.freed++
			if allocation.freed > 1 {
				return
			} // Record a double-free without crashing the native test process.
			if allocation.answer {
				allocation.scrubbed = true
				for _, value := range unsafe.Slice((*byte)(unsafe.Pointer(pointer)), int(allocation.size)) {
					if value != 0 {
						allocation.scrubbed = false
					}
				}
			}
		}
		base.free(pointer)
	}
	panicked := false
	api.strnlen = func(pointer, maximum uintptr) uintptr {
		if fault == "native-reader-panic" && !panicked {
			panicked = true
			panic("fixture panic detail must not escape")
		}
		return base.strnlen(pointer, maximum)
	}
	transaction := &darwinPamTransaction{api: &api, handle: 1}
	transaction.handlerID = darwinPamNextHandlerID.Add(1)
	darwinPamHandlers.Store(transaction.handlerID, transaction)
	t.Cleanup(func() { darwinPamHandlers.Delete(transaction.handlerID) })
	var callback func(int32, uintptr, *uintptr, uintptr) int32
	purego.RegisterFunc(&callback, darwinPamConversationPointer)
	invocations, endCalls, environmentCalls := 0, 0, 0
	trigger := func() {
		invocations++
		count := messageCount
		vector := messages
		if fault == "zero-count" {
			count = 0
		}
		if fault == "excess-count" {
			count = darwinPamMaximumMessages + 1
		}
		if fault == "nil-messages" {
			vector = 0
		}
		var response uintptr
		out := &response
		if fault == "nil-responses" {
			out = nil
		}
		status := callback(count, vector, out, transaction.handlerID)
		require.NotEqual(t, darwinPamSuccess, status)
		require.Zero(t, response, "failed native framing must not publish response memory")
	}
	api.pamSetItem = func(uintptr, int32, string) int32 { return darwinPamSuccess }
	api.pamAuthenticate = func(uintptr, int32) int32 {
		if (phase == "operation" || phase == "operation-and-end") && primary {
			trigger()
		}
		return darwinPamSuccess
	}
	api.pamAcctMgmt = func(uintptr, int32) int32 {
		if (phase == "operation" || phase == "operation-and-end") && !primary {
			trigger()
		}
		return darwinPamSuccess
	}
	api.pamGetItem = func(_ uintptr, _ int32, out *uintptr) int32 { *out = username; return darwinPamSuccess }
	api.pamGetenvlist = func(uintptr) uintptr {
		environmentCalls++
		list := base.calloc(2, unsafe.Sizeof(uintptr(0)))
		require.NotZero(t, list)
		value := base.calloc(uintptr(len("FRESH=fixture")+1), 1)
		require.NotZero(t, value)
		copy(unsafe.Slice((*byte)(unsafe.Pointer(value)), len("FRESH=fixture")+1), "FRESH=fixture")
		*(*uintptr)(unsafe.Pointer(list)) = value
		return list // Transaction owns and frees both allocations if reached.
	}
	api.pamEnd = func(uintptr, int32) int32 {
		endCalls++
		if phase == "end" || phase == "operation-and-end" {
			trigger()
		}
		if endFailure {
			return darwinPamSystemErr
		}
		return darwinPamSuccess
	}
	start := func(_, _ string, handler func(int32, string) (string, error)) (darwinPamTransactionLike, error) {
		transaction.handler = handler
		if phase == "start" {
			trigger()
		}
		return transaction, nil
	}
	var handler func(int32, string) (string, error)
	handlerCalls := 0
	if primary {
		handler = func(int32, string) (string, error) {
			handlerCalls++
			if fault == "typed-handler-denial" {
				return "", &darwinPamError{code: darwinPamCredInsufficient}
			}
			if fault == "handler-panic" || (fault == "second-message-handler-panic" && handlerCalls == 2) {
				panic("fixture handler panic detail must not escape")
			}
			return "fixture answer", nil
		}
	}
	name, env, accepted, err := authorizeWithDarwinPam(darwinPamOptions{Context: t.Context(), Service: "owned-fixture", Username: "alice", Authenticate: primary}, handler, start)
	if fault == "typed-handler-denial" && !endFailure && phase != "operation-and-end" {
		require.NoError(t, err, "already handled credential denial is not a cleanup error")
	} else {
		require.Error(t, err)
		require.NotContains(t, err.Error(), "fixture panic detail")
		require.NotContains(t, err.Error(), "fixture handler panic detail")
	}
	require.Empty(t, name)
	require.Nil(t, env)
	require.False(t, accepted)
	expectedInvocations := 1
	if phase == "none" {
		expectedInvocations = 0
	}
	if phase == "operation-and-end" {
		expectedInvocations = 2
	}
	require.Equal(t, expectedInvocations, invocations)
	require.Equal(t, 1, endCalls)
	if phase != "end" && phase != "none" {
		require.Zero(t, environmentCalls)
	}
	_, registered := darwinPamHandlers.Load(transaction.handlerID)
	require.False(t, registered, "callback ownership must retire even after ignored native errors")
	answers := 0
	for _, allocation := range tracked {
		require.Equal(t, 1, allocation.freed, "each allocated native response block must be freed once")
		if allocation.answer {
			answers++
			require.True(t, allocation.scrubbed, "native answer bytes must be scrubbed before free")
		}
	}
	if strings.HasPrefix(fault, "second-message-") {
		require.Equal(t, 1, answers, "exercise cleanup after one successful answer allocation")
	}
}

func TestDarwinPamNativeCallbackFailureIsStickyAndFirstWins(t *testing.T) {
	first := errors.New("first callback failure")
	transaction := &darwinPamTransaction{}
	transaction.setCallbackError(first)
	transaction.setCallbackError(errors.New("later failure"))
	err := transaction.call(func() int32 { t.Fatal("latched failure reached another native operation"); return darwinPamSuccess })
	require.ErrorIs(t, err, first)
	env, err := transaction.GetEnvList()
	require.Nil(t, env)
	require.ErrorIs(t, err, first)
}
