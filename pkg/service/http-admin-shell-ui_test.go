package service

import (
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
	"testing"
)

func TestBrowserManagementDrawerGridAndKeepAlive(t *testing.T) {
	testBrowserLoginUi(t, true, "admin-shell", func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		conf.Flows[0].Http.KeepAlive = template.MustNewEnforceable[template.Duration]("10s")
		conf.Session.V.(*configuration.SessionFs).MaxConnections = 1
	})
}

func TestBrowserManagementSessionRecordingEventRelations(t *testing.T) {
	testBrowserLoginUi(t, true, "management-relations", func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{AllowArtifactTransfer: true}
		conf.Session.V.(*configuration.SessionFs).MaxConnections = 1
	})
}
