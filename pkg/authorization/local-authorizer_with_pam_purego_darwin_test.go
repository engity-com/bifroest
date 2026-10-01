//go:build darwin && !without_pam

package authorization

import (
	"testing"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/stretchr/testify/require"
)

func TestDarwinPuregoPamLoadsSystemAPI(t *testing.T) {
	api, err := loadDarwinPam()
	require.NoError(t, err)
	require.NotNil(t, api)
	require.NotEmpty(t, api.pamStrerror(0, darwinPamSystemErr))
}

func TestDarwinPuregoPamStructLayouts(t *testing.T) {
	require.Equal(t, uintptr(16), unsafe.Sizeof(darwinPamConversationDescriptor{}))
	require.Equal(t, uintptr(8), unsafe.Offsetof(darwinPamConversationDescriptor{}.AppData))
	require.Equal(t, uintptr(16), unsafe.Sizeof(darwinPamMessage{}))
	require.Equal(t, uintptr(8), unsafe.Offsetof(darwinPamMessage{}.Message))
	require.Equal(t, uintptr(16), unsafe.Sizeof(darwinPamResponse{}))
	require.Equal(t, uintptr(8), unsafe.Offsetof(darwinPamResponse{}.ReturnCode))
}

func TestDarwinPuregoPamNilEnvironmentIsFailure(t *testing.T) {
	transaction := &darwinPamTransaction{api: &darwinPamAPI{
		pamGetenvlist: func(uintptr) uintptr { return 0 },
		pamStrerror:   func(uintptr, int32) string { return "out of memory" },
	}}

	environment, err := transaction.GetEnvList()
	require.Nil(t, environment)
	require.Error(t, err)
	var pamErr *darwinPamError
	require.ErrorAs(t, err, &pamErr)
	require.Equal(t, darwinPamBufErr, pamErr.code)
}

func TestDarwinPuregoPamAppleAccountLocksAreDenials(t *testing.T) {
	require.True(t, isDarwinPamDenial(&darwinPamError{code: darwinPamAppleAcctTempLock}))
	require.True(t, isDarwinPamDenial(&darwinPamError{code: darwinPamAppleAcctLocked}))
}

func TestDarwinPuregoPamConversationCallback(t *testing.T) {
	api, err := loadDarwinPam()
	require.NoError(t, err)

	transaction := &darwinPamTransaction{
		api: api,
		handler: func(style int32, message string) (string, error) {
			require.Equal(t, darwinPamPromptEchoOff, style)
			require.Equal(t, "Password:", message)
			return "secret", nil
		},
	}
	transaction.handlerID = darwinPamNextHandlerID.Add(1)
	darwinPamHandlers.Store(transaction.handlerID, transaction)
	t.Cleanup(func() { darwinPamHandlers.Delete(transaction.handlerID) })

	messageText := api.calloc(uintptr(len("Password:")+1), 1)
	require.NotZero(t, messageText)
	defer api.free(messageText)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(messageText)), len("Password:")+1), "Password:")
	message := darwinPamMessage{Style: darwinPamPromptEchoOff, Message: messageText}
	messagePointer := api.calloc(1, unsafe.Sizeof(message))
	require.NotZero(t, messagePointer)
	defer api.free(messagePointer)
	*(*darwinPamMessage)(unsafe.Pointer(messagePointer)) = message
	messages := api.calloc(1, unsafe.Sizeof(uintptr(0)))
	require.NotZero(t, messages)
	defer api.free(messages)
	*(*uintptr)(unsafe.Pointer(messages)) = messagePointer

	var callback func(int32, uintptr, *uintptr, uintptr) int32
	purego.RegisterFunc(&callback, darwinPamConversationPointer)
	var responses uintptr
	status := callback(1, messages, &responses, transaction.handlerID)
	require.Equal(t, darwinPamSuccess, status)
	require.NotZero(t, responses)
	response := (*darwinPamResponse)(unsafe.Pointer(responses))
	actual, err := darwinPamCString(api, response.Response, darwinPamMaximumResponseSize+1)
	require.NoError(t, err)
	require.Equal(t, "secret", actual)
	darwinPamScrubAndFree(api, response.Response, darwinPamMaximumResponseSize+1)
	api.free(responses)
}
