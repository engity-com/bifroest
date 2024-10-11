package main

import (
	"fmt"
)

type archiveFormat uint8

const (
	packFormatTgz archiveFormat = iota
	packFormatZip
)

func (this archiveFormat) String() string {
	v, ok := packFormatToString[this]
	if !ok {
		return fmt.Sprintf("illegal-archive-format-%d", this)
	}
	return v
}

func (this archiveFormat) ext() string {
	return "." + this.String()
}

func (this *archiveFormat) Set(plain string) error {
	v, ok := stringToPackFormat[plain]
	if !ok {
		return fmt.Errorf("illegal-archive-format: %s", plain)
	}
	*this = v
	return nil
}

var (
	packFormatToString = map[archiveFormat]string{
		packFormatTgz: "tgz",
		packFormatZip: "zip",
	}
	stringToPackFormat = func(in map[archiveFormat]string) map[string]archiveFormat {
		result := make(map[string]archiveFormat, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(packFormatToString)
)
