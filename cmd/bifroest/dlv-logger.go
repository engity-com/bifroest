package main

import (
	"io"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/consumer"
	"github.com/go-delve/delve/pkg/logflags"
)

func init() {
	logflags.SetLoggerFactory(func(flag bool, f logflags.Fields, out io.Writer) logflags.Logger {
		lvl := level.Warn
		if flag {
			lvl = level.Debug
		}
		provider := &native.Provider{
			Level:    lvl,
			Consumer: native.DefaultProvider.Consumer,
		}

		if out != nil {
			provider.Consumer = consumer.NewWriter(out, func(target *consumer.Writer) {
				target.Formatter = native.DefaultProvider.Consumer.(*consumer.Writer).Formatter
			})
		}
		source := provider.GetLogger("dlv")
		var result dlvLogger
		if lfv, ok := source.(log.LoggerFacade); ok {
			result = dlvLogger{lfv}
		} else {
			result = dlvLogger{log.NewLoggerFacade(func() log.CoreLogger {
				return source
			})}
		}
		if f != nil {
			return result.WithFields(f)
		}
		return &result
	})
}

type dlvLogger struct {
	log.LoggerFacade
}

func (instance *dlvLogger) Printf(format string, args ...interface{}) {
	instance.logf(level.Info, format, args...)
}

func (instance *dlvLogger) Warningf(format string, args ...interface{}) {
	instance.logf(level.Warn, format, args...)
}

func (instance *dlvLogger) Panicf(format string, args ...interface{}) {
	instance.logf(level.Error, format, args...)
}

func (instance *dlvLogger) Print(args ...interface{}) {
	instance.log(level.Info, args...)
}

func (instance *dlvLogger) Warning(args ...interface{}) {
	instance.log(level.Warn, args...)
}

func (instance *dlvLogger) Panic(args ...interface{}) {
	instance.log(level.Error, args...)
}

func (instance *dlvLogger) Debugln(args ...interface{}) {
	instance.log(level.Debug, args...)
}

func (instance *dlvLogger) Infoln(args ...interface{}) {
	instance.log(level.Info, args...)
}

func (instance *dlvLogger) Println(args ...interface{}) {
	instance.log(level.Info, args...)
}

func (instance *dlvLogger) Warnln(args ...interface{}) {
	instance.log(level.Warn, args...)
}

func (instance *dlvLogger) Warningln(args ...interface{}) {
	instance.log(level.Warn, args...)
}

func (instance *dlvLogger) Errorln(args ...interface{}) {
	instance.log(level.Error, args...)
}

func (instance *dlvLogger) Fatalln(args ...interface{}) {
	instance.log(level.Fatal, args...)
}

func (instance *dlvLogger) Panicln(args ...interface{}) {
	instance.log(level.Error, args...)
}

func (instance *dlvLogger) WithField(key string, value interface{}) logflags.Logger {
	return &dlvLogger{instance.LoggerFacade.With(key, value).(log.LoggerFacade)}
}

func (instance *dlvLogger) WithFields(fields logflags.Fields) logflags.Logger {
	return &dlvLogger{instance.LoggerFacade.WithAll(fields).(log.LoggerFacade)}
}

func (instance *dlvLogger) WithError(err error) logflags.Logger {
	return &dlvLogger{instance.LoggerFacade.WithError(err).(log.LoggerFacade)}
}

func (instance *dlvLogger) log(level level.Level, args ...interface{}) {
	instance.DoLog(level, 2, args...)
}

func (instance *dlvLogger) logf(level level.Level, format string, args ...interface{}) {
	instance.DoLogf(level, 2, format, args...)
}
