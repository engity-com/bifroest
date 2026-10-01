//go:build unix && !darwin

package configuration

var (
	defaultSessionFsStorage = "/var/lib/engity/bifroest/sessions"
)
