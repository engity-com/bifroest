package service

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"

	"github.com/engity-com/bifroest/pkg/management/protocol"
)

// Keep matching server-side. Shared protocol validation must not drag server
// collation dependencies into the closed, separately inventoried WASM cores.
func managementGridPredicate(f *protocol.GridFilter, operation protocol.ReadOperation) func(map[string]protocol.GridValue) bool {
	if f == nil {
		return func(map[string]protocol.GridValue) bool { return true }
	}
	kind := f.Kind(operation)
	value := strings.TrimSpace(f.Value)
	var choices []string
	if f.Operator == "isAnyOf" {
		_ = json.Unmarshal([]byte(f.Value), &choices)
	}
	number, _ := strconv.ParseFloat(value, 64)
	when, _ := protocol.RecordingTime(value)
	when = when.Truncate(time.Minute)
	equality := collate.New(language.Und, collate.IgnoreCase, collate.IgnoreDiacritics)
	equal := func(a, b string) bool { return equality.CompareString(a, b) == 0 }
	return func(fields map[string]protocol.GridValue) bool {
		current, present := fields[f.Field]
		if !present {
			return false
		}
		switch f.Operator {
		case "isEmpty":
			return current.Empty
		case "isNotEmpty":
			return !current.Empty
		}
		if kind == "string" {
			text := strings.ToLower(current.Text)
			wanted := strings.ToLower(value)
			switch f.Operator {
			case "contains":
				return strings.Contains(text, wanted)
			case "doesNotContain":
				return !strings.Contains(text, wanted)
			case "equals", "is":
				return equal(current.Text, value)
			case "doesNotEqual", "not":
				return !equal(current.Text, value)
			case "startsWith":
				return strings.HasPrefix(text, wanted)
			case "endsWith":
				return strings.HasSuffix(text, wanted)
			case "isAnyOf":
				for _, choice := range choices {
					if equal(current.Text, strings.TrimSpace(choice)) {
						return true
					}
				}
				return false
			}
		}
		if current.Empty {
			return false
		}
		if kind == "boolean" {
			return current.Boolean == (value == "true")
		}
		if kind == "number" {
			switch f.Operator {
			case "=":
				return current.Number == number
			case "!=":
				return current.Number != number
			case ">":
				return current.Number > number
			case ">=":
				return current.Number >= number
			case "<":
				return current.Number < number
			case "<=":
				return current.Number <= number
			case "isAnyOf":
				for _, choice := range choices {
					v, _ := strconv.ParseFloat(choice, 64)
					if current.Number == v {
						return true
					}
				}
				return false
			}
		}
		if kind == "dateTime" {
			switch f.Operator {
			case "is":
				return current.Time.Truncate(time.Minute).Equal(when)
			case "not":
				return !current.Time.Truncate(time.Minute).Equal(when)
			case "after":
				return current.Time.After(when)
			case "onOrAfter":
				return !current.Time.Before(when)
			case "before":
				return current.Time.Before(when)
			case "onOrBefore":
				return !current.Time.After(when)
			}
		}
		return false
	}
}
