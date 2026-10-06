package service

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
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
}
