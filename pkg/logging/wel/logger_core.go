//go:build windows

package wel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/echocat/slf4g/fields"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
)

// RootLoggerName specifies the name of the root version of coreLogger
// instances which are managed by Provider.
const RootLoggerName = "ROOT"

type coreLogger struct {
	*Provider
}

// Log implements log.CoreLogger#Log(event).
func (instance *coreLogger) Log(event log.Event, skipFrames uint16) {
	instance.log(instance.GetName(), event, skipFrames+1)
}

func (instance *coreLogger) log(loggerName string, event log.Event, _ uint16) {
	l := event.GetLevel()
	if !instance.IsLevelEnabled(l) {
		return
	}

	if v := log.GetLoggerOf(event, instance); v == nil {
		event = event.With(instance.GetFieldKeysSpec().GetLogger(), loggerName)
	}

	if l >= level.Error {
		_ = instance.base.Error(1, instance.format(event))
	} else {
		_ = instance.base.Info(0, instance.format(event))
	}
}

// IsLevelEnabled implements log.CoreLogger#IsLevelEnabled()
func (instance *coreLogger) IsLevelEnabled(v level.Level) bool {
	return instance.GetLevel().CompareTo(v) <= 0
}

// GetName implements log.CoreLogger#GetName()
func (instance *coreLogger) GetName() string {
	return RootLoggerName
}

// GetProvider implements log.CoreLogger#GetProvider()
func (instance *coreLogger) GetProvider() log.Provider {
	return instance.Provider
}

func (instance *coreLogger) NewEvent(l level.Level, values map[string]interface{}) log.Event {
	return instance.NewEventWithFields(l, fields.WithAll(values))
}

func (instance *coreLogger) NewEventWithFields(l level.Level, f fields.ForEachEnabled) log.Event {
	asFields, err := fields.AsFields(f)
	if err != nil {
		panic(err)
	}
	return &event{
		provider: instance.Provider,
		fields:   asFields,
		level:    l,
	}
}

func (instance *coreLogger) Accepts(e log.Event) bool {
	return e != nil
}

func (instance *coreLogger) format(event log.Event) string {
	buf := new(bytes.Buffer)

	_, _ = buf.WriteString(instance.formatLevel(event.GetLevel()))
	_, _ = buf.WriteString(instance.formatMessage(event))
	messageKey := instance.GetFieldKeysSpec().GetMessage()
	loggerKey := instance.GetFieldKeysSpec().GetLogger()
	timestampKey := instance.GetFieldKeysSpec().GetTimestamp()
	if err := fields.SortedForEach(event, nil, func(k string, vp interface{}) error {
		if vl, ok := vp.(fields.Filtered); ok {
			fv, shouldBeRespected := vl.Filter(event)
			if !shouldBeRespected {
				return nil
			}
			vp = fv
		} else if vl, ok := vp.(fields.Lazy); ok {
			vp = vl.Get()
		}
		if vp == fields.Exclude {
			return nil
		}

		if k == loggerKey && vp == RootLoggerName {
			return nil
		}
		if k == messageKey || k == timestampKey {
			return nil
		}
		v, err := instance.formatValue(vp)
		if err != nil {
			return err
		}

		_ = buf.WriteByte(' ')
		_, _ = buf.WriteString(k)
		_ = buf.WriteByte('=')
		_, _ = buf.Write(v)
		return nil
	}); err != nil {
		_ = instance.base.Error(1123, fmt.Sprintf("Cannot format event %v: %v", event, err))
		return ""
	}

	return buf.String()
}

func (instance *coreLogger) formatLevel(l level.Level) string {
	return "[" + instance.getLevelFormatter().Format(l) + "]"
}

func (instance *coreLogger) formatMessage(event log.Event) string {
	var message string
	if v := log.GetMessageOf(event, instance); v != nil {
		message = *v

		message = strings.TrimLeftFunc(message, func(r rune) bool {
			return r == '\r' || r == '\n'
		})
		message = strings.TrimRightFunc(message, unicode.IsSpace)
		message = strings.TrimFunc(message, func(r rune) bool {
			return r == '\r' || !unicode.IsGraphic(r)
		})
		message = strings.ReplaceAll(message, "\n", "\u23CE")
		if message != "" {
			message = " " + message
		}
	}
	return message
}

func (instance *coreLogger) formatValue(v interface{}) ([]byte, error) {
	if ve, ok := v.(error); ok {
		v = ve.Error()
	}
	return json.Marshal(v)
}
