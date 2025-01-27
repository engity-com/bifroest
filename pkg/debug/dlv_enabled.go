//go:build embedded_dlv

package debug

func IsEmbeddedDlvEnabled() bool {
	return true
}

func GetDlvBuildTags() []string {
	return []string{"embedded_dlv"}
}
