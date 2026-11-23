//go:build unix && !darwin

package configuration

const DefaultHttpAcmeStorage = "/var/lib/engity/bifroest/http/acme"

const DefaultHttpCertificateFile = "/etc/engity/bifroest/tls/tls.crt"
const DefaultHttpPrivateKeyFile = "/etc/engity/bifroest/tls/tls.key"
