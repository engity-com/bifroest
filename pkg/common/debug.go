package common

import (
	"encoding/json"
	"strings"
)

func ToDebugString(formatted bool, what any) string {
	var buf strings.Builder
	encoder := json.NewEncoder(&buf)
	if formatted {
		encoder.SetIndent("", "   ")
	}
	_ = encoder.Encode(what)
	return buf.String()
}
