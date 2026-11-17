package serve

// Shared with platform-neutral parsing/help tests; only Windows opts embeds it.
type internalOptions struct {
	WindowsService bool `flag:"internal.windowsService" visible:"false" default:"false" description:"Internal Windows SCM entry point."`
}
