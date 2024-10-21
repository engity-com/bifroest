package logger

import (
	"time"

	"github.com/echocat/slf4g/fields"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
)

const RootLoggerName = "ROOT"

type CoreLogger struct {
	provider *Provider
	name     string
	level    level.Level
}

// Log implements log.CoreLogger#Log(event).
func (this *CoreLogger) Log(event log.Event, _ uint16) {
	f := this.provider.Drain
	if f == nil {
		return
	}
	if !this.IsLevelEnabled(event.GetLevel()) {
		return
	}

	if v := log.GetTimestampOf(event, this.provider); v == nil {
		event = event.With(this.provider.GetFieldKeysSpec().GetTimestamp(), time.Now())
	}
	if v := log.GetLoggerOf(event, this.provider); v == nil {
		event = event.With(this.provider.GetFieldKeysSpec().GetLogger(), this)
	}

	f(event)
}

// GetLevel returns the current level.Level where this log.CoreLogger is set to.
func (this *CoreLogger) GetLevel() level.Level {
	if v := this.level; v != 0 {
		return v
	}
	return this.provider.GetLevel()
}

// SetLevel changes the current level.Level of this log.CoreLogger. If set to
// 0 it will force this CoreLogger to use DefaultLevel.
func (this *CoreLogger) SetLevel(v level.Level) {
	this.level = v
}

// IsLevelEnabled implements log.CoreLogger#IsLevelEnabled()
func (this *CoreLogger) IsLevelEnabled(v level.Level) bool {
	return this.GetLevel().CompareTo(v) <= 0
}

// GetName implements log.CoreLogger#GetName()
func (this *CoreLogger) GetName() string {
	return this.name
}

// GetProvider implements log.CoreLogger#GetProvider()
func (this *CoreLogger) GetProvider() log.Provider {
	return this.provider
}

func (this *CoreLogger) NewEvent(l level.Level, values map[string]interface{}) log.Event {
	return this.NewEventWithFields(l, fields.WithAll(values))
}

func (this *CoreLogger) NewEventWithFields(l level.Level, f fields.ForEachEnabled) log.Event {
	asFields, err := fields.AsFields(f)
	if err != nil {
		panic(err)
	}
	return &event{
		provider: this.provider,
		fields:   asFields,
		level:    l,
	}
}

func (this *CoreLogger) Accepts(e log.Event) bool {
	return e != nil
}
