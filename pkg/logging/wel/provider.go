//go:build windows

package wel

import (
	"sync"
	_ "unsafe"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	"github.com/echocat/slf4g/level"
	tlevel "github.com/echocat/slf4g/sdk/testlog/level"
	"golang.org/x/sys/windows/svc/eventlog"
)

// NewProvider creates a new instance of Provider which is ready to use.
func NewProvider(name string, base *eventlog.Log, level level.Level) *Provider {
	result := &Provider{name: name, base: base, level: level}

	return result
}

// Provider is an implementation of log.Provider which ensures that everything is
// logged using testing.TB#Log(). Use NewProvider(..) to get a new instance.
type Provider struct {
	base  *eventlog.Log
	name  string
	level level.Level

	coreLogger *coreLogger
	logger     log.Logger
	initLogger sync.Once
}

func (instance *Provider) initIfRequired() {
	instance.initLogger.Do(func() {
		instance.coreLogger = &coreLogger{instance}
		instance.logger = log.NewLogger(instance.coreLogger)
	})
}

// GetRootLogger implements log.Provider#GetRootLogger()
func (instance *Provider) GetRootLogger() log.Logger {
	instance.initIfRequired()
	return instance.logger
}

// GetLogger implements log.Provider#GetLogger()
func (instance *Provider) GetLogger(name string) log.Logger {
	if name == RootLoggerName {
		return instance.GetRootLogger()
	}

	instance.initIfRequired()
	return log.NewLogger(&coreLoggerRenamed{instance.coreLogger, name})
}

// GetName implements log.Provider#GetName()
func (instance *Provider) GetName() string {
	return instance.name
}

// GetAllLevels implements log.Provider#GetAllLevels()
func (instance *Provider) GetAllLevels() level.Levels {
	return level.GetProvider().GetLevels()
}

// GetFieldKeysSpec implements log.Provider#GetFieldKeysSpec()
func (instance *Provider) GetFieldKeysSpec() fields.KeysSpec {
	return &fields.KeysSpecImpl{}
}

// GetLevel returns the current level.Level where this log.Provider is set to.
func (instance *Provider) GetLevel() level.Level {
	return instance.level
}

// SetLevel changes the current level.Level of this log.Provider. If set to
// 0 it will force this Provider to use DefaultLevel.
func (instance *Provider) SetLevel(v level.Level) {
	instance.level = v
}

func (instance *Provider) getLevelFormatter() tlevel.Formatter {
	return tlevel.DefaultFormatter
}
