package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/recording"
)

func (this *service) managementArtifactAllowed(auth authorization.Authorization) bool {
	if auth == nil || !auth.IsAuthorized() {
		return false
	}
	// No exact forced artifact equivalence has been proved. Read ceilings for
	// metadata must not accidentally permit original evidence transfers.
	if key := authorization.AuthorizedKeyPolicyOf(auth); key != nil && key.ForcedCommand != nil {
		return false
	}
	for _, flow := range this.Configuration.Flows {
		if flow.Name == auth.Flow() {
			management, ok := flow.Environment.V.(*configuration.EnvironmentManagement)
			return ok && management.AllowArtifactTransfer
		}
	}
	return false
}

func (this *service) RunManagementArtifact(task environment.TaskContext, request protocol.ArtifactRequest, output io.Writer, _ bool, allowArtifactTransfer bool) (int, error) {
	if task == nil || task.Authorization() == nil || task.Authorization().FindSession() == nil || task.Authorization().FindSession().Flow() != task.Authorization().Flow() || !allowArtifactTransfer || !this.managementArtifactAllowed(task.Authorization()) || request.Validate() != nil {
		return -1, errManagementPolicy
	}
	name := configuration.AuditlogName(request.Auditlog)
	if err := name.Validate(); err != nil {
		return -1, err
	}
	switch request.Operation {
	case protocol.DownloadRecording:
		var id recording.Id
		if err := id.UnmarshalText([]byte(request.ID)); err != nil {
			return -1, err
		}
		if err := this.writeManagementRecording(task.Context(), name, id, output); err != nil {
			return -1, err
		}
	case protocol.DownloadAudit:
		if err := this.writeManagementAudit(task.Context(), name, output); err != nil {
			return -1, err
		}
	default:
		return -1, protocol.ErrRequest
	}
	return 0, nil
}

func (this *service) executeManagementArtifact(conn *terminalConnection, request protocol.ArtifactRequest, output io.Writer, endData func() error) (int, error) {
	if conn == nil || output == nil || endData == nil || !this.managementArtifactAllowed(conn.authorization) || request.Validate() != nil {
		return -1, errManagementPolicy
	}
	input, err := json.Marshal(request)
	if err != nil {
		return -1, err
	}
	stream := &managementArtifactByteStream{managementByteStream: managementByteStream{conn: conn, input: bytes.NewReader(input)}, output: output}
	source := &managementArtifactSource{managementReadSource: managementReadSource{stream: stream}, artifact: request, endData: endData}
	return this.executeManagementSource(conn, source)
}

type managementArtifactSource struct {
	managementReadSource
	artifact protocol.ArtifactRequest
	endData  func() error
}

func (this *managementArtifactSource) Run(env environment.Environment, base environmentContext, _ environment.TaskType) (int, error) {
	if _, err := io.Copy(io.Discard, this.stream); err != nil {
		return -1, err
	}
	runner, ok := env.(environment.ManagementArtifactReader)
	if !ok {
		return -1, fmt.Errorf("environment has no artifact capability")
	}
	code, err := runner.ReadManagementArtifact(&managementReadTask{base}, this.artifact, this.stream)
	if err != nil || code != 0 {
		return code, err
	}
	// This boundary only ends data. The HTTP adapter alone can append success,
	// after the common driver has sealed recording and completed final audit.
	if err := this.endData(); err != nil {
		return -1, err
	}
	return 0, nil
}

type managementArtifactByteStream struct {
	managementByteStream
	output io.Writer
}

func (this *managementArtifactByteStream) Write(data []byte) (int, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if err := this.Context().Err(); err != nil {
		return 0, err
	}
	return this.output.Write(data)
}
func (this *managementArtifactByteStream) Stderr() io.ReadWriter { return this }
func (*managementArtifactByteStream) RawCommand() string         { return "structured-management-artifact-v1" }
