//go:build !darwin

package serve

func configureProcessLimits() error {
	return nil
}
