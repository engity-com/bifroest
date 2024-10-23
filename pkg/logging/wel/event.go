//go:build windows

package wel

import (
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	"github.com/echocat/slf4g/level"
)

type event struct {
	provider *Provider
	fields   fields.Fields
	level    level.Level
}

func (instance *event) ForEach(consumer func(key string, value interface{}) error) error {
	return instance.fields.ForEach(consumer)
}

func (instance *event) Get(key string) (interface{}, bool) {
	return instance.fields.Get(key)
}

func (instance *event) Len() int {
	return instance.fields.Len()
}

func (instance *event) GetLevel() level.Level {
	return instance.level
}

func (instance *event) With(key string, value interface{}) log.Event {
	return instance.with(func(s fields.Fields) fields.Fields {
		return s.With(key, value)
	})
}

func (instance *event) Withf(key string, format string, args ...interface{}) log.Event {
	return instance.with(func(s fields.Fields) fields.Fields {
		return s.Withf(key, format, args...)
	})
}

func (instance *event) WithError(err error) log.Event {
	return instance.with(func(s fields.Fields) fields.Fields {
		return s.With(instance.provider.GetFieldKeysSpec().GetError(), err)
	})
}

func (instance *event) WithAll(of map[string]interface{}) log.Event {
	return instance.with(func(s fields.Fields) fields.Fields {
		return s.WithAll(of)
	})
}

func (instance *event) Without(keys ...string) log.Event {
	return instance.with(func(s fields.Fields) fields.Fields {
		return s.Without(keys...)
	})
}

func (instance *event) with(mod func(fields.Fields) fields.Fields) log.Event {
	return &event{
		provider: instance.provider,
		fields:   mod(instance.fields),
		level:    instance.level,
	}
}
