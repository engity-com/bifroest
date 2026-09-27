package configuration

const (
	defaultMacosApplicationSupport = "/Library/Application Support/Engity/Bifroest"

	DefaultHostKeyLocation                  = defaultMacosApplicationSupport + "/key"
	DefaultCertificateIdentityFileLocation  = defaultMacosApplicationSupport + "/client-key"
	DefaultCertificateAuthorityFileLocation = defaultMacosApplicationSupport + "/ca"

	defaultAuditlogIdentityFile       = defaultMacosApplicationSupport + "/auditlog-key"
	defaultAuditlogJournalDirectory   = defaultMacosApplicationSupport + "/auditlog"
	defaultAuditlogRecordingDirectory = defaultMacosApplicationSupport + "/recordings"
)

var (
	defaultSessionFsStorage          = defaultMacosApplicationSupport + "/sessions"
	defaultAlternativesLocation      = defaultMacosApplicationSupport + `/binaries/{{.version}}/{{.os}}-{{.arch}}-{{.edition}}{{.ext}}`
	defaultAuthorizationHtpasswdFile = defaultMacosApplicationSupport + "/htpasswd"
)
