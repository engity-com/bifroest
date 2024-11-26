package build

import (
	"fmt"
)

type ArchiveFormat uint8

const (
	ArchiveFormatTgz ArchiveFormat = iota
	ArchiveFormatZip
)

func (this ArchiveFormat) String() string {
	v, ok := archiveFormatToString[this]
	if !ok {
		return fmt.Sprintf("illegal-archive-format-%d", this)
	}
	return v
}

func (this ArchiveFormat) Ext() string {
	return "." + this.String()
}

func (this *ArchiveFormat) Set(plain string) error {
	v, ok := stringToArchiveFormat[plain]
	if !ok {
		return fmt.Errorf("illegal-archive-format: %s", plain)
	}
	*this = v
	return nil
}

var (
	archiveFormatToString = map[ArchiveFormat]string{
		ArchiveFormatTgz: "tgz",
		ArchiveFormatZip: "zip",
	}
	stringToArchiveFormat = func(in map[ArchiveFormat]string) map[string]ArchiveFormat {
		result := make(map[string]ArchiveFormat, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(archiveFormatToString)
)
