//go:build unix && !darwin

package configuration

var (
	defaultAuthorizationHtpasswdFile = `/etc/engity/bifroest/htpasswd`
)
