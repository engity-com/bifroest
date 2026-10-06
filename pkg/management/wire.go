package management

import (
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

const WireCommand = "_bifroest-management-v1"
const maxWireRequestBytes = 64 << 10

type WireRequest struct {
	Version uint8    `cbor:"1,keyasint"`
	Args    []string `cbor:"2,keyasint"`
}

func EncodeWireRequest(args []string) ([]byte, error) {
	encoded, err := cbor.Marshal(WireRequest{Version: 1, Args: args})
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxWireRequestBytes {
		return nil, fmt.Errorf("management request exceeds %d bytes", maxWireRequestBytes)
	}
	return encoded, nil
}

func DecodeWireRequest(input io.Reader) ([]string, error) {
	encoded, err := io.ReadAll(io.LimitReader(input, maxWireRequestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxWireRequestBytes {
		return nil, fmt.Errorf("management request exceeds %d bytes", maxWireRequestBytes)
	}
	var request WireRequest
	if err := cbor.Unmarshal(encoded, &request); err != nil {
		return nil, err
	}
	if request.Version != 1 || len(request.Args) == 0 {
		return nil, fmt.Errorf("unsupported or empty management request")
	}
	for _, arg := range request.Args {
		if len(arg) > 16<<10 {
			return nil, fmt.Errorf("management argument exceeds 16 KiB")
		}
	}
	return request.Args, nil
}
