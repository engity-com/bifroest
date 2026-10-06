package service

import (
	"fmt"
	"strings"
	"testing"

	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

type managementWarningCapture struct {
	log.Logger
	warnings *[]string
}

func (this managementWarningCapture) With(string, any) log.Logger { return this }

func (this managementWarningCapture) Warn(values ...any) {
	*this.warnings = append(*this.warnings, fmt.Sprint(values...))
}

func TestManagementCredentialDisclosureEmitsStartupWarning(t *testing.T) {
	var warnings []string
	svc := &Service{Logger: managementWarningCapture{warnings: &warnings}, Configuration: configuration.Configuration{
		Flows: configuration.Flows{
			{Name: "safe", Environment: configuration.Environment{V: &configuration.EnvironmentManagement{}}},
			{Name: "debug", Environment: configuration.Environment{V: &configuration.EnvironmentManagement{IncludingCredentials: true}}},
		},
	}}
	svc.warnOnManagementCredentials()
	require.Len(t, warnings, 1)
	require.Contains(t, strings.ToLower(warnings[0]), "never in production")
}
