package service

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfssh "github.com/engity-com/bifroest/pkg/ssh"
)

type managementKeyOperations struct {
	service *service
}

func (this managementKeyOperations) Export(ctx context.Context, request model.KeyExportRequest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.Kind == "host" {
		address, err := bfssh.ParseAddress(request.Address)
		if err != nil {
			return nil, err
		}
		var output []byte
		for _, signer := range this.service.server.HostSigners {
			output = append(output, knownhosts.Line([]string{knownhosts.Normalize(address.String())}, signer.PublicKey())...)
			output = append(output, '\n')
		}
		if len(output) == 0 {
			return nil, fmt.Errorf("no active SSH host keys")
		}
		return output, nil
	}
	if request.Kind != "ca" && request.Kind != "public" {
		return nil, fmt.Errorf("unsupported public key export %q", request.Kind)
	}
	if err := request.Flow.Validate(); err != nil {
		return nil, err
	}
	if strings.ContainsAny(request.Comment, "\r\n") {
		return nil, fmt.Errorf("comment must not contain a line break")
	}
	repository, ok := this.service.environments.(interface {
		SshPublicKey(configuration.FlowName, bool, uint) (ssh.PublicKey, error)
	})
	if !ok {
		return nil, fmt.Errorf("configured SSH public identities are unavailable")
	}
	key, err := repository.SshPublicKey(request.Flow, request.Kind == "ca", request.IdentityIndex)
	if err != nil {
		return nil, err
	}
	output := bytes.TrimSpace(ssh.MarshalAuthorizedKey(key))
	if request.Comment != "" {
		output = append(append(output, ' '), request.Comment...)
	}
	return append(output, '\n'), nil
}
