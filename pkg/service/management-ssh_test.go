package service

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
	"github.com/engity-com/bifroest/pkg/recording"
)

func TestManagementFlowHandlesHumanAndCBORSSHExecWithoutShell(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
	})
	client, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{
		User: server.username, Auth: []gossh.AuthMethod{gossh.PublicKeys(server.signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	defer client.Close()

	human, err := client.NewSession()
	require.NoError(t, err)
	output, err := human.Output("flow ls --format=json")
	require.NoError(t, err)
	var flows []management.FlowSummary
	require.NoError(t, json.Unmarshal(output, &flows))
	require.Len(t, flows, 1)
	require.Equal(t, "management", flows[0].Environment)

	wire, err := client.NewSession()
	require.NoError(t, err)
	request, err := management.EncodeWireRequest([]string{"flow", "ls"})
	require.NoError(t, err)
	wire.Stdin = bytes.NewReader(request)
	response, err := wire.Output(management.WireCommand)
	require.NoError(t, err)
	var decoded []management.FlowSummary
	require.NoError(t, management.DecodeWireResult(bytes.NewReader(response), &decoded))
	require.Equal(t, flows, decoded)

	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.Shell())
	require.Error(t, sshSession.Wait())
	_ = sshSession.Close()

	forwarding, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, agent.RequestAgentForwarding(forwarding))
	_ = forwarding.Close()

	secretFile := filepath.Join(t.TempDir(), "management-secret")
	require.NoError(t, os.WriteFile(secretFile, []byte("never-export-this-credential"), 0600))
	responseFile, err := client.NewSession()
	require.NoError(t, err)
	var stderr bytes.Buffer
	responseFile.Stderr = &stderr
	_, err = responseFile.Output("flow ls @" + secretFile)
	require.Error(t, err)
	require.Contains(t, stderr.String(), "do not permit @file")
	require.NotContains(t, stderr.String(), "never-export-this-credential")
}

func TestManagementSSHExportsSignedLiveAuditSnapshot(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		parent := filepath.Dir(conf.Session.V.(*configuration.SessionFs).Storage)
		conf.Auditlogs[0].Enabled = true
		conf.Auditlogs[0].IdentityFile = filepath.Join(parent, "management-audit-signing-key")
		conf.Auditlogs[0].Directory = filepath.Join(parent, "management-audit")
	})
	client, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{
		User: server.username, Auth: []gossh.AuthMethod{gossh.PublicKeys(server.signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	defer client.Close()
	verify, err := client.NewSession()
	require.NoError(t, err)
	result, err := verify.Output("auditlog verify default")
	require.NoError(t, err)
	require.Equal(t, "verified (scope: full)\n", string(result))

	transfer, err := client.NewSession()
	require.NoError(t, err)
	defer transfer.Close()
	encoded, err := management.EncodeWireRequest([]string{"auditlog", "default"})
	require.NoError(t, err)
	transfer.Stdin = bytes.NewReader(encoded)
	stream, err := transfer.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, transfer.Start(management.WireAuditCommand))
	directory := t.TempDir()
	header, err := management.ReadAuditSnapshot(stream, directory)
	require.NoError(t, err)
	require.NoError(t, transfer.Wait())
	expected := server.service.auditIdentities["default"].ProducerId()
	require.Equal(t, expected.String(), header.Producer)
	verified, err := audit.VerifyJournals(t.Context(), []audit.JournalSource{{
		Name: "default", Directory: filepath.Join(directory, "journal"), ExpectedProducerId: expected,
	}})
	require.NoError(t, err)
	require.NotEmpty(t, verified.Records())
}

func TestManagementSSHStreamsSignedRecordingWithoutPrivateKeys(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		parent := filepath.Dir(conf.Session.V.(*configuration.SessionFs).Storage)
		conf.Auditlogs[0].IdentityFile = filepath.Join(parent, "management-signing-key")
		conf.Auditlogs[0].Recording.Enabled = true
		conf.Auditlogs[0].Recording.Directory = filepath.Join(parent, "management-recordings")
	})
	client, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{
		User: server.username, Auth: []gossh.AuthMethod{gossh.PublicKeys(server.signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	defer client.Close()
	command, err := client.NewSession()
	require.NoError(t, err)
	_, err = command.Output("flow ls")
	require.NoError(t, err)
	ids, err := server.service.recordingRepositories["default"].native.ListSealed(t.Context())
	require.NoError(t, err)
	require.Len(t, ids, 1)
	producer, err := client.NewSession()
	require.NoError(t, err)
	producerRequest, err := management.EncodeWireRequest([]string{"auditlog", "producer-id", "default"})
	require.NoError(t, err)
	producer.Stdin = bytes.NewReader(producerRequest)
	producerResponse, err := producer.Output(management.WireCommand)
	require.NoError(t, err)
	var producerID management.ProducerView
	require.NoError(t, management.DecodeWireResult(bytes.NewReader(producerResponse), &producerID))
	require.Equal(t, server.service.auditIdentities["default"].ProducerId().String(), producerID.ProducerID)

	transfer, err := client.NewSession()
	require.NoError(t, err)
	defer transfer.Close()
	encoded, err := management.EncodeWireRequest([]string{"recording", "default", ids[0].String()})
	require.NoError(t, err)
	transfer.Stdin = bytes.NewReader(encoded)
	stream, err := transfer.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, transfer.Start(management.WireRecordingCommand))
	var evidence bytes.Buffer
	header, err := management.ReadRecordingArtifact(stream, &evidence, recording.DefaultMaximumNativeRecordingBytes)
	require.NoError(t, err)
	require.NoError(t, transfer.Wait())
	require.Equal(t, ids[0].String(), header.ID)
	inspection, err := recording.Inspect(bytes.NewReader(evidence.Bytes()), int64(evidence.Len()), recording.InspectOptions{
		ExpectedProducerId: server.service.auditIdentities["default"].ProducerId(),
	})
	require.NoError(t, err)
	require.Equal(t, recording.FormatBcast, inspection.Format)
}

func TestManagementRecordingShowIgnoresUnrelatedCorruptArtifact(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		parent := filepath.Dir(conf.Session.V.(*configuration.SessionFs).Storage)
		conf.Auditlogs[0].IdentityFile = filepath.Join(parent, "management-signing-key")
		conf.Auditlogs[0].Recording.Enabled = true
		conf.Auditlogs[0].Recording.Directory = filepath.Join(parent, "management-recordings")
	})
	client, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{
		User: server.username, Auth: []gossh.AuthMethod{gossh.PublicKeys(server.signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	defer client.Close()
	initial, err := client.NewSession()
	require.NoError(t, err)
	_, err = initial.Output("flow ls")
	require.NoError(t, err)
	ids, err := server.service.recordingRepositories["default"].native.ListSealed(t.Context())
	require.NoError(t, err)
	require.Len(t, ids, 1)
	sealed := filepath.Join(server.service.Configuration.Auditlogs[0].Recording.Directory, "sealed")
	require.NoError(t, os.WriteFile(filepath.Join(sealed, "11111111-1111-4111-8111-111111111111.bcast"), []byte("corrupt"), 0600))
	sess, err := client.NewSession()
	require.NoError(t, err)
	output, err := sess.Output("recording show default " + ids[0].String() + " --format=json")
	require.NoError(t, err)
	var view management.RecordingView
	require.NoError(t, json.Unmarshal(output, &view))
	require.Equal(t, ids[0].String(), view.ID)
}
