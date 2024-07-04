package common

import (
	"encoding/json"
	"strings"
)

func ToDebugString(what any) string {
	var buf strings.Builder
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "   ")
	_ = encoder.Encode(what)
	return buf.String()
}
