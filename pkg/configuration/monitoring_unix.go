//go:build unix && !darwin

package configuration

const DefaultMonitoringCertificateFile = "/etc/engity/bifroest/tls/monitoring.crt"
const DefaultMonitoringPrivateKeyFile = "/etc/engity/bifroest/tls/monitoring.key"
