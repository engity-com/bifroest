package logger

import (
	"sync/atomic"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	"github.com/echocat/slf4g/level"
	"github.com/echocat/slf4g/native"
)

var (
	DefaultLevel = level.Info
)

type Provider struct {
	Level level.Level
	Drain func(log.Event)

	cache atomic.Pointer[log.LoggerCache]
}

func (this *Provider) rootFactory() log.Logger {
	return this.factory(RootLoggerName)
}

func (this *Provider) factory(name string) log.Logger {
	return log.NewLogger(&CoreLogger{
		this,
		name,
		0,
	})
}

// GetRootLogger implements log.Provider#GetRootLogger()
func (this *Provider) GetRootLogger() log.Logger {
	return this.getCache().GetRootLogger()
}

// GetLogger implements log.Provider#GetLogger()
func (this *Provider) GetLogger(name string) log.Logger {
	return this.getCache().GetLogger(name)
}

// GetName implements log.Provider#GetName()
func (this *Provider) GetName() string {
	return "imp"
}

// GetAllLevels implements log.Provider#GetAllLevels()
func (this *Provider) GetAllLevels() level.Levels {
	return level.GetProvider().GetLevels()
}

// GetFieldKeysSpec implements log.Provider#GetFieldKeysSpec()
func (this *Provider) GetFieldKeysSpec() fields.KeysSpec {
	return native.DefaultFieldKeysSpec
}

// GetLevel returns the current level.Level where this log.Provider is set to.
func (this *Provider) GetLevel() level.Level {
	if v := this.Level; v != 0 {
		return v
	}
	return DefaultLevel
}

// SetLevel changes the current level.Level of this log.Provider. If set to
// 0 it will force this Provider to use DefaultLevel.
func (this *Provider) SetLevel(v level.Level) {
	this.Level = v
}

func (this *Provider) getCache() log.LoggerCache {
	for {
		v := this.cache.Load()
		if v != nil {
			return *v
		}

		c := log.NewLoggerCache(this.rootFactory, this.factory)
		if this.cache.CompareAndSwap(nil, &c) {
			return c
		}
	}
}
