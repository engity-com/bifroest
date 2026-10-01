//go:build unix && !darwin

package configuration

const (
	defaultAuditlogIdentityFile     = "/etc/engity/bifroest/auditlog-key"
	defaultAuditlogJournalDirectory = "/var/lib/engity/bifroest/auditlog"
)
