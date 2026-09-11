//go:build windows

package configuration

const (
	DefaultHostKeyLocation                  = `C:\ProgramData\Engity\Bifroest\key`
	DefaultCertificateIdentityFileLocation  = `C:\ProgramData\Engity\Bifroest\client-key`
	DefaultCertificateAuthorityFileLocation = `C:\ProgramData\Engity\Bifroest\ca`
)
