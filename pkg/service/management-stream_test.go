package service

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/environment"
)

type managementStreamLogCapture struct {
	log.Logger
	messages *[]string
	cause    error
}

func (this managementStreamLogCapture) WithError(err error) log.Logger {
	this.cause = err
	return this
}

func (this managementStreamLogCapture) Error(values ...any) {
	*this.messages = append(*this.messages, fmt.Sprint(values...)+": "+this.cause.Error())
}

type managementStreamTestSession struct {
	essh.Session
	input  *bytes.Reader
	output bytes.Buffer
	errors bytes.Buffer
}

func (*managementStreamTestSession) RawCommand() string {
	return transport.WireRecordingListStreamCommand
}
func (this *managementStreamTestSession) Read(p []byte) (int, error)  { return this.input.Read(p) }
func (this *managementStreamTestSession) Write(p []byte) (int, error) { return this.output.Write(p) }
func (this *managementStreamTestSession) Stderr() io.ReadWriter       { return &this.errors }

type managementStreamTestTask struct {
	environment.Task
	session essh.Session
}

func (this managementStreamTestTask) SshSession() essh.Session { return this.session }

func TestManagementStreamFailureIsLoggedAndSentToStderrAndClient(t *testing.T) {
	var messages []string
	svc := &service{Service: &Service{Logger: managementStreamLogCapture{messages: &messages}}}
	sess := &managementStreamTestSession{input: bytes.NewReader([]byte{0xff})}
	code, err := svc.RunManagementCommand(managementStreamTestTask{session: sess}, false, false)
	require.Error(t, err)
	require.NotZero(t, code)
	require.Len(t, messages, 1)
	require.Contains(t, messages[0], "management command failed")
	require.Contains(t, messages[0], err.Error())
	require.Contains(t, sess.errors.String(), err.Error())
	decodeErr := transport.DecodeRecordingListStream(&sess.output, func(model.RecordingView) error {
		t.Fatal("a failed request must not yield metadata")
		return nil
	})
	require.ErrorContains(t, decodeErr, err.Error())
}
