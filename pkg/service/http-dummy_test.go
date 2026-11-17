package service

import (
	"fmt"
	"strings"
	"testing"

	"github.com/echocat/slf4g/level"
	"github.com/echocat/slf4g/testing/recording"
	"github.com/stretchr/testify/require"
)

func TestServiceDummyCertificateEmitsAnExplicitWarning(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	conf.Http.Tls.Acme.Enabled = false
	conf.Http.Tls.Dummy = true
	logger := recording.NewLogger()
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}, Logger: logger}).prepare()
	require.NoError(t, err)
	defer svc.Close()
	messageKey := logger.GetProvider().GetFieldKeysSpec().GetMessage()
	warnings := 0
	for _, event := range logger.GetAll() {
		message, _ := event.Get(messageKey)
		if strings.Contains(fmt.Sprint(message), "http.tls.dummy=true") {
			require.Equal(t, level.Warn, event.GetLevel())
			require.Contains(t, fmt.Sprint(message), "self-signed")
			require.Contains(t, fmt.Sprint(message), "testing only")
			require.NotContains(t, fmt.Sprint(message), "PRIVATE KEY")
			warnings++
		}
	}
	require.Equal(t, 1, warnings)
	require.NoError(t, svc.https.Prepare(t.Context()))
	require.True(t, svc.https.Ready())
	require.NoDirExists(t, conf.Http.Tls.Acme.Storage)
}
