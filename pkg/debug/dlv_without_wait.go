//go:build !dlv_wait

package debug

func ShouldEmbeddedDlvWait() bool {
	return false
}
