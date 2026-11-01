package service

import (
	"testing"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestBrowserKeepAliveUiLockedEditableFlowIsolationAndPersistence(t *testing.T) {
	testBrowserLoginUi(t, true, "keepalive", func(conf *configuration.Configuration) {
		conf.Flows[0].Http.KeepAlive = template.MustNewDuration(`{{if eq .authentication.principal "alice"}}10s{{else}}!20s{{end}}`)
		auth := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		auth.Entries = append(auth.Entries, configuration.AuthorizationSimpleEntry{Name: "bob", Password: crypto.Password("plain:correct")})
		other := conf.Flows[0]
		other.Name, other.DiscoverAsSlug = "keepalive-other", "Other"
		other.Http.KeepAlive = template.MustNewDuration("30s")
		conf.Flows = append(conf.Flows, other)
	})
}
