package client

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/management/wire"
)

// NewHTTPTransferResponse consumes ownership of an already-open HTTP body, also
// on validation error. Request creation, TLS/origin/auth scope, omitted cookies
// and redirect refusal belong to the trusted opening adapter, not this decoder.
func NewHTTPTransferResponse(response *http.Response, request protocol.ArtifactRequest) (*TransferResponse, error) {
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("missing HTTP artifact response")
	}
	media := response.Header.Values("Content-Type")
	if response.StatusCode != http.StatusOK || len(media) != 1 || media[0] != wire.TransferMediaType || len(response.Header.Values("Content-Encoding")) != 0 || response.Uncompressed {
		return nil, errors.Join(fmt.Errorf("HTTP artifact response was not accepted"), response.Body.Close())
	}
	result, err := NewTransferResponse(response.Body, request)
	if err != nil {
		return nil, errors.Join(err, response.Body.Close())
	}
	return result, nil
}
