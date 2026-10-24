// Package policy interprets a narrow, proven subset of operator-configured SSH
// forced commands as read ceilings. It never parses a browser command or runs CLI.
package policy

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/anmitsu/go-shlex"

	"github.com/engity-com/bifroest/pkg/management/protocol"
)

type ReadCeiling struct {
	Operation             protocol.ReadOperation
	Flow, User, State, ID string
	TableList             bool
	WholeSeconds          bool
}

// ForcedRead accepts only spellings whose effective CLI operation is proven.
// Unsupported aliases/flags/duplicate options are denied, never guessed. The
// SSH dispatcher and mutations deliberately remain outside this read ceiling.
func ForcedRead(raw string) (ReadCeiling, error) {
	deny := func() (ReadCeiling, error) {
		return ReadCeiling{}, fmt.Errorf("unsupported structured forced-command policy")
	}
	if len(raw) > 16<<10 || !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
		return deny()
	}
	args, err := shlex.Split(raw, true)
	if err != nil || len(args) < 2 {
		return deny()
	}
	ceiling := ReadCeiling{}
	switch args[0] + " " + args[1] {
	case "flow ls":
		ceiling.Operation = protocol.ListFlows
	case "session ls":
		ceiling.Operation = protocol.ListSessions
		ceiling.State = "active"
	case "session show":
		ceiling.Operation = protocol.ShowSession
	default:
		return deny()
	}
	format := "table"
	seen := map[string]bool{}
	for index := 2; index < len(args); index++ {
		arg := args[index]
		if !strings.HasPrefix(arg, "--") {
			if ceiling.Operation != protocol.ShowSession || ceiling.ID != "" || !protocol.ValidID(arg) {
				return deny()
			}
			ceiling.ID = arg
			continue
		}
		name, value, hasValue := strings.Cut(arg[2:], "=")
		if seen[name] {
			return deny()
		}
		seen[name] = true
		if !hasValue {
			index++
			if index >= len(args) {
				return deny()
			}
			value = args[index]
		}
		if strings.HasPrefix(value, "-") || strings.HasPrefix(value, "@") {
			return deny()
		}
		switch name {
		case "format":
			switch value {
			case "table", "json", "yaml", "cbor":
				format = value
			default:
				return deny()
			}
		case "flow":
			if ceiling.Operation != protocol.ListSessions {
				return deny()
			}
			ceiling.Flow = value
		case "user":
			if ceiling.Operation != protocol.ListSessions {
				return deny()
			}
			ceiling.User = value
		case "state":
			if ceiling.Operation != protocol.ListSessions {
				return deny()
			}
			switch value {
			case "active", "new", "authorized", "disposed", "all":
				ceiling.State = value
			default:
				return deny()
			}
		default:
			return deny()
		}
	}
	if ceiling.Operation == protocol.ShowSession && ceiling.ID == "" {
		return deny()
	}
	if ceiling.Operation == protocol.ListSessions {
		if _, err := (protocol.ReadRequest{Operation: protocol.ListSessions, Flow: ceiling.Flow, User: ceiling.User, State: ceiling.State}).Normalize(); err != nil {
			return deny()
		}
	}
	ceiling.TableList = ceiling.Operation == protocol.ListSessions && format == "table"
	ceiling.WholeSeconds = format == "table" || format == "cbor"
	return ceiling, nil
}

// Allows checks a normalized typed request; list filters are additionally
// intersected with this ceiling by the server, never replaced by caller values.
func (this ReadCeiling) Allows(request protocol.ReadRequest) bool {
	if this.Operation != request.Operation || this.Operation == protocol.ShowSession && this.ID != request.ID {
		return false
	}
	// Active is not merely an exposed state value: it also queries the exact
	// validity deadline. Do not turn hidden/second-precision metadata into a
	// finer-grained predicate oracle. Only an already-active forced command may
	// use that predicate; other exposed state filters can still narrow the rows.
	return this.Operation != protocol.ListSessions || request.State != "active" || this.State == "active"
}

func (this ReadCeiling) Project(item protocol.SessionItem) protocol.SessionItem {
	item.Owner = nil
	item.PolicyLimited = true
	if this.WholeSeconds {
		item.CreatedAt = item.CreatedAt.Truncate(time.Second)
		if item.LastAccessed != nil {
			value := item.LastAccessed.Truncate(time.Second)
			item.LastAccessed = &value
		}
		if item.ValidUntil != nil {
			value := item.ValidUntil.Truncate(time.Second)
			item.ValidUntil = &value
		}
	}
	if this.TableList {
		item.Remote = ""
		item.LastAccessed = nil
		item.ValidUntil = nil
	}
	return item
}
