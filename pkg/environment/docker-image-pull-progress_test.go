package environment

import (
	"strings"
	"testing"

	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"
)

func TestHandleImagePullProgressWithoutProgressTarget(t *testing.T) {
	input := strings.NewReader("{\"status\":\"Pulling from library/alpine\"}\n{\"status\":\"Status: Image is up to date for alpine\"}\n")
	require.NoError(t, handleImagePullProgress(input, nil, log.GetLogger("test")))
}

func TestHandleImagePullProgressReportsDaemonErrorWithoutProgressTarget(t *testing.T) {
	input := strings.NewReader("{\"errorDetail\":{\"message\":\"pull failed\"},\"error\":\"pull failed\"}\n")
	require.ErrorContains(t, handleImagePullProgress(input, nil, log.GetLogger("test")), "pull failed")
}
