package common

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func FindConfigured(conf *configuration.Configuration, name configuration.AuditlogName) (*configuration.Auditlog, error) {
	if conf == nil {
		return nil, fmt.Errorf("nil configuration")
	}
	for index := range conf.Auditlogs {
		if conf.Auditlogs[index].Name == name {
			return &conf.Auditlogs[index], nil
		}
	}
	return nil, fmt.Errorf("auditlog %q does not exist", name)
}
