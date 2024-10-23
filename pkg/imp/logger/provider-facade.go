package logger

import (
	"sync/atomic"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	"github.com/echocat/slf4g/level"
)

type ProviderFacade struct {
	delegate atomic.Pointer[log.Provider]
	cache    atomic.Pointer[log.LoggerCache]
}

func (this *ProviderFacade) getRootLogger() log.Logger {
	return log.NewLoggerFacade(func() log.CoreLogger {
		return this.getDelegate().GetRootLogger()
	})
}

func (this *ProviderFacade) getLogger(name string) log.Logger {
	return log.NewLoggerFacade(func() log.CoreLogger {
		return this.getDelegate().GetLogger(name)
	})
}

// GetRootLogger implements log.Provider#GetRootLogger()
func (this *ProviderFacade) GetRootLogger() log.Logger {
	return this.getCache().GetRootLogger()
}

// GetLogger implements log.Provider#GetLogger()
func (this *ProviderFacade) GetLogger(name string) log.Logger {
	return this.getCache().GetLogger(name)
}

// GetName implements log.Provider#GetName()
func (this *ProviderFacade) GetName() string {
	return this.getDelegate().GetName()
}

// GetAllLevels implements log.Provider#GetAllLevels()
func (this *ProviderFacade) GetAllLevels() level.Levels {
	return this.getDelegate().GetAllLevels()
}

// GetFieldKeysSpec implements log.Provider#GetFieldKeysSpec()
func (this *ProviderFacade) GetFieldKeysSpec() fields.KeysSpec {
	return this.getDelegate().GetFieldKeysSpec()
}

func (this *ProviderFacade) Set(delegate log.Provider) {
	if delegate == nil {
		delegate = log.GetProvider()
	}
	this.delegate.Store(&delegate)
}

func (this *ProviderFacade) getDelegate() log.Provider {
	for {
		if v := this.delegate.Load(); v != nil {
			return *v
		}
		def := log.GetProvider()
		if this.delegate.CompareAndSwap(nil, &def) {
			return def
		}
	}
}

func (this *ProviderFacade) getCache() log.LoggerCache {
	for {
		if v := this.cache.Load(); v != nil {
			return *v
		}
		created := log.NewLoggerCache(this.getRootLogger, this.getLogger)
		if this.cache.CompareAndSwap(nil, &created) {
			return created
		}
	}
}
