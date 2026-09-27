//go:build darwin && !cgo

package protocol

import "fmt"

func readDarwinProcessArguments(int) ([]byte, error) {
	return nil, fmt.Errorf("Darwin process environment lookup requires cgo")
}
