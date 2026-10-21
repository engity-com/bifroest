package audit

import "github.com/engity-com/bifroest/pkg/configuration"

// ConfiguredAuditlogOptions selects an existing auditlog. Offline journal
// commands use configuration.AuditlogNameOpts instead: that argument has a
// default and can be used as a label without a configured auditlog.
type ConfiguredAuditlogOptions struct {
	Name configuration.AuditlogName `argument:"auditlogName" required:"true" description:"Configured auditlog name."`
}
