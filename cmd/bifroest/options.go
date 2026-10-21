package main

import (
	"context"
	"fmt"

	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/facade/value"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

// Executable-only logging options do not appear in the SSH management schema.
// The compiled definition is immutable; parsing creates these values per run.
type opts struct {
	common.SSHConfigOpts
	LogLevel     string `flag:"log.level" description:"Minimum log level."`
	LogFormat    string `flag:"log.format" description:"Log formatter."`
	LogColorMode string `flag:"log.colorMode" description:"Color mode: auto, always or never."`
}

func configureExecutableLogging(ctx context.Context, options opts) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	provider := value.NewProvider(native.DefaultProvider)
	if options.LogLevel != "" {
		if err := provider.Level.Set(options.LogLevel); err != nil {
			return fmt.Errorf("--log.level: %w", err)
		}
	}
	if options.LogFormat != "" {
		if err := provider.Consumer.Formatter.Set(options.LogFormat); err != nil {
			return fmt.Errorf("--log.format: %w", err)
		}
	}
	if options.LogColorMode != "" {
		if provider.Consumer.Formatter.ColorMode == nil {
			return fmt.Errorf("--log.colorMode is not supported by the configured formatter")
		}
		if err := provider.Consumer.Formatter.ColorMode.Set(options.LogColorMode); err != nil {
			return fmt.Errorf("--log.colorMode: %w", err)
		}
	}
	return nil
}
