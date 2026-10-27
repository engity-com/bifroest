package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/terminal"
)

func (this *service) executeManagementRead(conn *terminalConnection, request protocol.ReadRequest) ([]byte, error) {
	request, err := request.Normalize()
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errManagementPolicy
	}
	if _, err := managementReadCeiling(conn.authorization, request); err != nil {
		return nil, err
	}
	return this.executeManagement(conn, &managementReadSource{request: request}, request)
}

func (this *service) executeManagementAction(conn *terminalConnection, permission *webManagementConfirmation) ([]byte, error) {
	if permission == nil || permission.request.Validate() != nil {
		return nil, errManagementConfirmation
	}
	if conn == nil || managementActionPolicy(conn.authorization, permission.request) != nil {
		return nil, errManagementPolicy
	}
	phase := "confirm"
	if permission.preparing {
		phase = "prepare"
	}
	return this.executeManagement(conn, &managementReadSource{action: permission}, struct {
		Phase string `json:"phase"`
		protocol.SessionAction
	}{phase, permission.request})
}

func (this *service) executeManagement(conn *terminalConnection, source *managementReadSource, payload any) ([]byte, error) {
	if conn == nil {
		return nil, errManagementPolicy
	}
	if source.action != nil {
		if err := managementActionPolicy(conn.authorization, source.action.request); err != nil {
			return nil, err
		}
	} else if _, err := managementReadCeiling(conn.authorization, source.request); err != nil {
		return nil, err
	}
	input, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	buffer := &managementByteStream{conn: conn, input: bytes.NewReader(input)}
	source.stream = buffer
	status, err := this.executeManagementSource(conn, source)
	if err != nil || status != 0 {
		if err == nil {
			err = fmt.Errorf("management returned a failure status")
		}
		return nil, err
	}
	return buffer.result(), nil
}

func (this *service) executeManagementSource(conn *terminalConnection, source executionSource) (int, error) {
	if conn == nil || conn.service != this || conn.IsClosed() || !this.isManagementFlow(conn.authorization.Flow()) {
		return -1, errManagementPolicy
	}
	if !conn.used.CompareAndSwap(false, true) {
		return -1, fmt.Errorf("connection already has an execution")
	}
	if err := conn.activity(); err != nil {
		return -1, err
	}
	base := environmentContext{service: this, connection: conn, authorization: conn.authorization, executionContext: conn.Lifetime()}
	if err := this.validateTerminalAuthorization(&base); err != nil {
		return -1, err
	}
	key := authorization.AuthorizedKeyPolicyOf(conn.authorization)
	return this.execute(&executionRequest{base: base, connection: conn, source: source, taskType: environment.TaskTypeShell, requestedTask: audit.SessionTaskExec, command: true, forced: key != nil && key.ForcedCommand != nil})
}

// The shared driver captures bounded structured bytes. This is neither a shell
// nor a terminal command interpreter; the environment receives typed data.
type managementReadSource struct {
	stream     terminal.Stream
	unrecorded terminal.Stream
	request    protocol.ReadRequest
	action     *webManagementConfirmation
}

func (this *managementReadSource) Terminal() terminal.Stream { return this.stream }
func (this *managementReadSource) Close() error              { return this.stream.Close() }
func (this *managementReadSource) Capture(sink recordingSink, elapsed func() time.Duration, onFailure func(error)) (*terminalCapture, error) {
	capture, err := newRecordedTerminalWithPty(this.stream, terminalRecordingPty{}, sink, elapsed, onFailure)
	if err != nil {
		return nil, err
	}
	this.unrecorded = this.stream
	this.stream = capture
	return capture.terminalCapture, nil
}
func (this *managementReadSource) DiscardCapture() {
	if this.unrecorded != nil {
		this.stream = this.unrecorded
		this.unrecorded = nil
	}
}
func (this *managementReadSource) Request(base environmentContext) environment.Request {
	return &terminalEnvironmentRequest{base}
}
func (*managementReadSource) Prepared(session.State) error { return nil }
func (this *managementReadSource) Run(env environment.Environment, base environmentContext, _ environment.TaskType) (int, error) {
	// Record only the normalized typed request, never the slug/bearer or raw HTTP
	// body. Keep its output private until capture/seal/final audit have succeeded.
	if _, err := io.Copy(io.Discard, this.stream); err != nil {
		return -1, err
	}
	if this.action != nil {
		runner, ok := env.(environment.ManagementActor)
		if !ok {
			return -1, fmt.Errorf("environment has no structured action capability")
		}
		base.executionContext = context.WithValue(base.Context(), managementActionContextKey{}, this.action)
		return runner.ActManagement(&managementReadTask{base}, this.action.request, this.stream)
	}
	runner, ok := env.(environment.ManagementReader)
	if !ok {
		return -1, fmt.Errorf("environment has no structured management capability")
	}
	return runner.ReadManagement(&managementReadTask{base}, this.request, this.stream)
}

type managementReadTask struct{ environmentContext }

func (*managementReadTask) TaskType() environment.TaskType { return environment.TaskTypeShell }

type managementByteStream struct {
	conn   *terminalConnection
	mutex  sync.Mutex
	input  *bytes.Reader
	output bytes.Buffer
}

func (this *managementByteStream) Context() context.Context { return this.conn.Lifetime() }
func (this *managementByteStream) Read(data []byte) (int, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if err := this.Context().Err(); err != nil {
		return 0, err
	}
	return this.input.Read(data)
}
func (this *managementByteStream) Write(data []byte) (int, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if err := this.Context().Err(); err != nil {
		return 0, err
	}
	if len(data) > protocol.MaximumResponseBytes-this.output.Len() {
		return 0, fmt.Errorf("management response exceeds bound")
	}
	return this.output.Write(data)
}
func (this *managementByteStream) result() []byte {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return bytes.Clone(this.output.Bytes())
}
func (this *managementByteStream) Close() error          { return this.conn.Close() }
func (*managementByteStream) CloseWrite() error          { return nil }
func (this *managementByteStream) Stderr() io.ReadWriter { return this }
func (this *managementByteStream) RawCommand() string    { return "structured-management-read-v1" }
func (*managementByteStream) Environ() []string          { return nil }
func (*managementByteStream) Pty() (terminal.Pty, <-chan terminal.Window, bool) {
	return terminal.Pty{}, nil, false
}
func (*managementByteStream) Signals(chan<- terminal.Signal) {}
