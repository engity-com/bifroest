package debug

func GetTargetBuildTags(plus ...string) []string {
	return append(plus, GetDlvBuildTags()...)
}
