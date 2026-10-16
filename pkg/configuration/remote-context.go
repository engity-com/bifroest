package configuration

import "context"

type remoteConfigurationKey struct{}

// ContextWithoutLocalConfiguration prevents decoding a local file for a
// command that will be forwarded to another Bifröst instance.
func ContextWithoutLocalConfiguration(ctx context.Context) context.Context {
	return context.WithValue(ctx, remoteConfigurationKey{}, true)
}

func RemoteConfigurationForbidden(ctx context.Context) bool {
	forbidden, _ := ctx.Value(remoteConfigurationKey{}).(bool)
	return forbidden
}
