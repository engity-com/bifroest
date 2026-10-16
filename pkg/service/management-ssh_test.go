package service

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	cliformat "github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/recording"
)

func TestServiceOwnsManagementApplication(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
	})
	application := server.service.managementApplication
	require.NotNil(t, application)
	options := &cli.ParseOpts{Profiles: []string{common.ProfileManagement}}
	var output bytes.Buffer
	ctx := cli.ContextWithStdio(t.Context(), nil, &output, nil)
	require.NoError(t, application.ParseAndExecute(ctx, options, "version"))
	require.NotEmpty(t, output.String())
	require.NoError(t, server.stop())
	require.Error(t, application.ParseAndExecute(ctx, options, "version"))
}

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
	var flows []model.FlowSummary
	require.NoError(t, json.Unmarshal(output, &flows))
	require.Len(t, flows, 1)
	require.Equal(t, "management", flows[0].Environment)
	versionSession, err := client.NewSession()
	require.NoError(t, err)
	versionOutput, err := versionSession.Output("version")
	require.NoError(t, err)
	require.Contains(t, string(versionOutput), "Version:  test")
	shortVersionSession, err := client.NewSession()
	require.NoError(t, err)
	shortVersionOutput, err := shortVersionSession.Output("version --long=false")
	require.NoError(t, err)
	require.Contains(t, string(shortVersionOutput), "Bifroest test")
	require.NotContains(t, string(shortVersionOutput), "Version:")
	auditSession, err := client.NewSession()
	require.NoError(t, err)
	auditOutput, err := auditSession.Output("audit ls --format=json")
	require.NoError(t, err)
	require.Contains(t, string(auditOutput), `"name":"default"`)
	legacy, err := client.NewSession()
	require.NoError(t, err)
	_, err = legacy.Output("auditlog ls")
	require.Error(t, err)

	wire, err := client.NewSession()
	require.NoError(t, err)
	request, err := transport.EncodeWireRequest([]string{"flow", "ls"})
	require.NoError(t, err)
	wire.Stdin = bytes.NewReader(request)
	response, err := wire.Output(transport.WireCommand)
	require.NoError(t, err)
	var decoded []model.FlowSummary
	require.NoError(t, transport.DecodeWireResult(bytes.NewReader(response), &decoded))
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

	for _, command := range []string{transport.WireAuditCommand, transport.WireRecordingCommand} {
		transfer, err := client.NewSession()
		require.NoError(t, err)
		request, err := transport.EncodeWireRequest([]string{"auditlog", "default"})
		require.NoError(t, err)
		transfer.Stdin = bytes.NewReader(request)
		var stderr bytes.Buffer
		transfer.Stderr = &stderr
		content, err := transfer.Output(command)
		require.Error(t, err)
		require.Empty(t, content)
		require.Contains(t, stderr.String(), "allowArtifactTransfer")
	}
	for _, command := range []string{"audit events --with-sensitive default", "audit export --with-sensitive default", "audit merge --with-sensitive default"} {
		query, err := client.NewSession()
		require.NoError(t, err)
		var stderr bytes.Buffer
		query.Stderr = &stderr
		content, err := query.Output(command)
		require.Error(t, err)
		require.Empty(t, content)
		require.Contains(t, stderr.String(), "allowArtifactTransfer")
	}
}

func TestManagementSSHExportsSignedLiveAuditSnapshot(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{AllowArtifactTransfer: true}
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
	result, err := verify.Output("audit verify default")
	require.NoError(t, err)
	require.Equal(t, "verified (scope: full)\n", string(result))
	sensitive, err := client.NewSession()
	require.NoError(t, err)
	result, err = sensitive.Output("audit events --with-sensitive default --format=json")
	require.NoError(t, err)
	var events []audit.VerifiedRecord
	require.NoError(t, json.Unmarshal(result, &events))
	require.NotEmpty(t, events)

	transfer, err := client.NewSession()
	require.NoError(t, err)
	defer transfer.Close()
	encoded, err := transport.EncodeWireRequest([]string{"auditlog", "default"})
	require.NoError(t, err)
	transfer.Stdin = bytes.NewReader(encoded)
	stream, err := transfer.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, transfer.Start(transport.WireAuditCommand))
	directory := t.TempDir()
	header, err := transport.ReadAuditSnapshot(stream, directory)
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
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{AllowArtifactTransfer: true}
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
	producerRequest, err := transport.EncodeWireRequest([]string{"audit", "producer-id", "default"})
	require.NoError(t, err)
	producer.Stdin = bytes.NewReader(producerRequest)
	producerResponse, err := producer.Output(transport.WireCommand)
	require.NoError(t, err)
	var producerID cliformat.ProducerView
	require.NoError(t, transport.DecodeWireResult(bytes.NewReader(producerResponse), &producerID))
	require.Equal(t, server.service.auditIdentities["default"].ProducerId().String(), producerID.ProducerID)

	transfer, err := client.NewSession()
	require.NoError(t, err)
	defer transfer.Close()
	encoded, err := transport.EncodeWireRequest([]string{"recording", "default", ids[0].String()})
	require.NoError(t, err)
	transfer.Stdin = bytes.NewReader(encoded)
	stream, err := transfer.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, transfer.Start(transport.WireRecordingCommand))
	var evidence bytes.Buffer
	header, err := transport.ReadRecordingArtifact(stream, &evidence, recording.DefaultMaximumNativeRecordingBytes)
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
	var view model.RecordingView
	require.NoError(t, json.Unmarshal(output, &view))
	require.Equal(t, ids[0].String(), view.ID)

	content, err := client.NewSession()
	require.NoError(t, err)
	var stderr bytes.Buffer
	content.Stderr = &stderr
	denied, err := content.Output("recording export --with-sensitive default " + ids[0].String())
	require.Error(t, err)
	require.Empty(t, denied)
	require.Contains(t, stderr.String(), "allowArtifactTransfer")
}
