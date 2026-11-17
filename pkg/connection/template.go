package connection

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/net"
)

// TemplateView contains only incoming connection metadata. It deliberately does
// not embed a Connection, socket, logger, context, credentials or control API.
type TemplateView struct {
	id        Id
	selection Selection
	remote    templateRemote
}

func NewTemplateView(conn Connection, selection Selection) (TemplateView, error) {
	if conn == nil {
		return TemplateView{}, fmt.Errorf("connection metadata unavailable")
	}
	selected, err := selection.Canonical()
	if err != nil {
		return TemplateView{}, err
	}
	peer := conn.Remote()
	if peer == nil {
		return TemplateView{}, fmt.Errorf("connection peer metadata unavailable")
	}
	return TemplateView{id: conn.Id(), selection: selected, remote: templateRemote{user: peer.User(), host: peer.Host().Clone()}}, nil
}

func TemplateViewOf(ctx Context) (TemplateView, error) {
	selection, err := SelectionOf(ctx)
	if err != nil {
		return TemplateView{}, err
	}
	return NewTemplateView(ctx.Connection(), selection)
}

// Keep the existing pure metadata spellings available to older templates.
func (v TemplateView) Id() Id               { return v.id }
func (v TemplateView) Remote() net.Remote   { return v.remote }
func (v TemplateView) Selection() Selection { return v.selection }

func (v TemplateView) GetField(name string) (any, bool, error) {
	switch name {
	case "id":
		return v.id.String(), true, nil
	case "transport":
		return string(v.selection.Transport), true, nil
	case "remote":
		return v.remote, true, nil
	case "http":
		if v.selection.Transport != TransportHttp {
			return nil, true, nil
		}
		return templateHttp{host: v.selection.Host, slug: v.selection.Slug}, true, nil
	default:
		return nil, false, nil
	}
}

type templateRemote struct {
	user string
	host net.Host
}

func (v templateRemote) User() string   { return v.user }
func (v templateRemote) Host() net.Host { return v.host.Clone() }
func (v templateRemote) String() string { return v.user + "@" + v.host.String() }
func (v templateRemote) GetField(name string) (any, bool, error) {
	switch name {
	case "user":
		return v.user, true, nil
	case "host":
		return v.host.Clone(), true, nil
	default:
		return nil, false, nil
	}
}

type templateHttp struct{ host, slug string }

func (v templateHttp) GetField(name string) (any, bool, error) {
	switch name {
	case "host":
		return v.host, true, nil
	case "slug":
		return v.slug, true, nil
	default:
		return nil, false, nil
	}
}
