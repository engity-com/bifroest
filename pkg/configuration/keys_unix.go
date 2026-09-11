//go:build unix

package configuration

const (
	DefaultHostKeyLocation                  = "/etc/engity/bifroest/key"
	DefaultCertificateIdentityFileLocation  = "/etc/engity/bifroest/client-key"
	DefaultCertificateAuthorityFileLocation = "/etc/engity/bifroest/ca"
)
