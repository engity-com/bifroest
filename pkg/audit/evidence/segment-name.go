package evidence

import (
	"strconv"
	"strings"
)

func AuditSegmentName(sequence uint64, hash Hash, encrypted bool) string {
	extension := ".baudit"
	if encrypted {
		extension = ".beaudit"
	}
	value := strconv.FormatUint(sequence, 10)
	return "segment-" + strings.Repeat("0", 20-len(value)) + value + "-" + hash.String() + extension
}

func ParseAuditSegmentName(name string, encrypted bool) (uint64, Hash, bool) {
	extension := ".baudit"
	if encrypted {
		extension = ".beaudit"
	}
	if !strings.HasPrefix(name, "segment-") || !strings.HasSuffix(name, extension) {
		return 0, Hash{}, false
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(name, "segment-"), extension)
	if len(middle) != 85 || middle[20] != '-' {
		return 0, Hash{}, false
	}
	sequence, err := strconv.ParseUint(middle[:20], 10, 64)
	if err != nil || sequence == 0 {
		return 0, Hash{}, false
	}
	var hash Hash
	if hash.UnmarshalText([]byte(middle[21:])) != nil || AuditSegmentName(sequence, hash, encrypted) != name {
		return 0, Hash{}, false
	}
	return sequence, hash, true
}
