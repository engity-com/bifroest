package protocol

import (
	"encoding/json"
	"math"
	"strconv"
	"time"
)

// GridFilter narrows already-authorized projected metadata. It is never a
// selector, command, regular expression or permission. Community has one item.
type GridFilter struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

func (f GridFilter) Kind(operation ReadOperation) string {
	var texts, dates, numbers, booleans []string
	switch operation {
	case ListFlows:
		texts = []string{"name", "authorization", "environment", "auditlog"}
	case ListSessions:
		texts = []string{"id", "flow", "user", "state", "remote"}
		dates = []string{"createdAt"}
	case ListAuditlogs:
		texts = []string{"name"}
		booleans = []string{"enabled", "recordingEnabled", "encrypted"}
	case ListRecordings:
		texts = []string{"id", "flow", "user", "target", "status", "format"}
		dates = []string{"startedAt", "endedAt"}
		numbers = []string{"duration", "containerBytes"}
		booleans = []string{"encrypted"}
	case ListAuditEvents:
		texts = []string{"id", "name", "domain", "outcome", "flow", "reason", "sessionId"}
		dates = []string{"recordedAt"}
	}
	for kind, fields := range map[string][]string{"string": texts, "dateTime": dates, "number": numbers, "boolean": booleans} {
		for _, field := range fields {
			if f.Field == field {
				return kind
			}
		}
	}
	return ""
}

func (f GridFilter) Validate(operation ReadOperation) error {
	if !text(f.Value, 2048) {
		return ErrRequest
	}
	kind := f.Kind(operation)
	if kind == "" {
		return ErrRequest
	}
	if f.Operator == "isEmpty" || f.Operator == "isNotEmpty" {
		if kind == "boolean" || f.Value != "" {
			return ErrRequest
		}
		return nil
	}
	if f.Operator == "isAnyOf" {
		if kind != "string" && kind != "number" {
			return ErrRequest
		}
		var values []string
		if json.Unmarshal([]byte(f.Value), &values) != nil || len(values) == 0 || len(values) > 16 {
			return ErrRequest
		}
		for _, value := range values {
			if !text(value, 256) {
				return ErrRequest
			}
			if kind == "number" {
				v, err := strconv.ParseFloat(value, 64)
				if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
					return ErrRequest
				}
			}
		}
		return nil
	}
	if f.Value == "" {
		return ErrRequest
	}
	switch kind {
	case "string":
		switch f.Operator {
		case "contains", "doesNotContain", "equals", "doesNotEqual", "startsWith", "endsWith", "is", "not":
			return nil
		}
	case "number":
		if v, err := strconv.ParseFloat(f.Value, 64); err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			return ErrRequest
		}
		switch f.Operator {
		case "=", "!=", ">", ">=", "<", "<=":
			return nil
		}
	case "dateTime":
		if _, err := RecordingTime(f.Value); err != nil {
			return ErrRequest
		}
		switch f.Operator {
		case "is", "not", "after", "onOrAfter", "before", "onOrBefore":
			return nil
		}
	case "boolean":
		if f.Operator == "is" && (f.Value == "true" || f.Value == "false") {
			return nil
		}
	}
	return ErrRequest
}

type GridValue struct {
	Text    string
	Number  float64
	Time    time.Time
	Boolean bool
	Empty   bool
}

func GridText(value string) GridValue    { return GridValue{Text: value, Empty: value == ""} }
func GridTime(value time.Time) GridValue { return GridValue{Time: value, Empty: value.IsZero()} }
func GridNumber(value float64) GridValue { return GridValue{Number: value} }
func GridBoolean(value bool) GridValue   { return GridValue{Boolean: value} }
