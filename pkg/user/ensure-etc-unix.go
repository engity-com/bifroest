//go:build moo && unix && !android

package user

type EtcUnixEnsurer struct {
	AllowBadNames      bool
	SkipIllegalEntries bool

	PasswdFile string
	GroupFile  string
	ShadowFile string
}
