//go:build !embedded_dlv

package debug

func IsEmbeddedDlvEnabled() bool {
	return false
}

func GetDlvBuildTags() []string {
	return []string{}
}
