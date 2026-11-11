package connection

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/net"
)

type Transport string

const (
	TransportSsh  Transport = "ssh"
	TransportHttp Transport = "http"
)

// Selection describes the logical incoming request, not the downstream
// environment. HTTP/2 requests may share a socket but have different selections.
type Selection struct {
	Transport Transport
	Host      string
	Slug      string
}

type SelectionProvider interface {
	Selection() Selection
}

// SelectionOf preserves existing SSH request implementations. A non-SSH
// adapter must explicitly provide its transport and selection. Unknown explicit
// transports fail closed instead of accidentally inheriting SSH semantics.
func SelectionOf(request Context) (Selection, error) {
	if provider, ok := request.(SelectionProvider); ok {
		return provider.Selection().Canonical()
	}
	return Selection{Transport: TransportSsh}, nil
}

func (this Selection) Canonical() (Selection, error) {
	switch this.Transport {
	case TransportSsh:
		if this.Host != "" || this.Slug != "" {
			return Selection{}, fmt.Errorf("SSH selection must not contain HTTP host or slug")
		}
	case TransportHttp:
		host, err := net.CanonicalHttpHost(this.Host)
		if err != nil {
			return Selection{}, err
		}
		if err := net.ValidateHttpSlug(this.Slug); err != nil {
			return Selection{}, err
		}
		this.Host = host
	default:
		return Selection{}, fmt.Errorf("unknown incoming transport")
	}
	return this, nil
}
