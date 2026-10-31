package policy

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/anmitsu/go-shlex"

	"github.com/engity-com/bifroest/pkg/management/protocol"
)

type ActionCeiling struct {
	Action, ID string
}

// ForcedAction recognizes only the existing CLI's single-ID session actions.
// Format changes presentation, not authority. Global ID ambiguity must still be
// checked against the live repository, since the CLI does not accept a flow.
func ForcedAction(raw string) (ActionCeiling, error) {
	deny := func() (ActionCeiling, error) {
		return ActionCeiling{}, fmt.Errorf("unsupported structured forced-command policy")
	}
	if len(raw) > 16<<10 || !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
		return deny()
	}
	args, err := shlex.Split(raw, true)
	if err != nil || len(args) < 3 || args[0] != "session" || args[1] != "disconnect" && args[1] != "dispose" {
		return deny()
	}
	ceiling := ActionCeiling{Action: args[1]}
	seenFormat := false
	for index := 2; index < len(args); index++ {
		arg := args[index]
		if protocol.ValidID(arg) && ceiling.ID == "" {
			ceiling.ID = arg
			continue
		}
		name, value, hasValue := strings.Cut(arg, "=")
		if name != "--format" || seenFormat {
			return deny()
		}
		seenFormat = true
		if !hasValue {
			index++
			if index == len(args) {
				return deny()
			}
			value = args[index]
		}
		switch value {
		case "table", "json", "yaml", "cbor":
		default:
			return deny()
		}
	}
	if ceiling.ID == "" {
		return deny()
	}
	return ceiling, nil
}

func (this ActionCeiling) Allows(request protocol.SessionAction) bool {
	return request.Validate() == nil && this.Action == request.Action && this.ID == request.ID
}
