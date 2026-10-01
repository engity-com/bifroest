//go:build !darwin

package main

func configureProcessLimits() error {
	return nil
}
