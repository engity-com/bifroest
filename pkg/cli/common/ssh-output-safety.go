package common

import (
	"context"
	"fmt"
	"io"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

// EnsureConfiguredSSHOutputSafe protects static configured SSH identities and
// trust files. It does not load keys, create files or render session templates.
func EnsureConfiguredSSHOutputSafe(ctx context.Context, output string, stdout io.Writer, conf *configuration.Configuration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	guard, err := newFileOutputGuard(output, stdout)
	if err != nil || guard == nil {
		return err
	}
	return checkConfiguredSSHFiles(ctx, conf, func(path, description string) error {
		return guard.check(ctx, path, description)
	})
}

func checkConfiguredSSHFiles(ctx context.Context, conf *configuration.Configuration, check func(string, string) error) error {
	if conf == nil {
		return fmt.Errorf("nil configuration")
	}
	checkStatic := func(configured template.String, description string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !configured.IsHardCoded() {
			return nil
		}
		return check(configured.String(), description)
	}
	for _, identity := range conf.Ssh.Keys.HostKeys {
		if err := checkStatic(identity, "SSH host identity"); err != nil {
			return err
		}
	}
	for _, flow := range conf.Flows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if ssh, ok := flow.Environment.V.(*configuration.EnvironmentSsh); ok {
			for _, identity := range ssh.IdentityFiles {
				if err := checkStatic(identity, fmt.Sprintf("flow %q SSH login identity", flow.Name)); err != nil {
					return err
				}
			}
			if ssh.Certificate != nil {
				if err := checkStatic(ssh.Certificate.IdentityFile, fmt.Sprintf("flow %q SSH certificate identity", flow.Name)); err != nil {
					return err
				}
				if err := checkStatic(ssh.Certificate.AuthorityIdentityFile, fmt.Sprintf("flow %q SSH certificate authority", flow.Name)); err != nil {
					return err
				}
			}
			if err := check(string(ssh.KnownHostsFile), fmt.Sprintf("flow %q SSH known-hosts file", flow.Name)); err != nil {
				return err
			}
		}
		var authorities string
		switch auth := flow.Authorization.V.(type) {
		case *configuration.AuthorizationSimple:
			authorities = string(auth.TrustedUserCAsFile)
			for _, entry := range auth.Entries {
				if err := check(string(entry.AuthorizedKeysFile), fmt.Sprintf("flow %q authorized-keys file", flow.Name)); err != nil {
					return err
				}
			}
		case *configuration.AuthorizationLocal:
			authorities = string(auth.TrustedUserCAsFile)
			for _, file := range auth.AuthorizedKeys {
				if err := checkStatic(file, fmt.Sprintf("flow %q authorized-keys file", flow.Name)); err != nil {
					return err
				}
			}
		case *configuration.AuthorizationBifroest:
			authorities = string(auth.TrustedUserCAsFile)
		}
		if err := check(authorities, fmt.Sprintf("flow %q trusted user-CA file", flow.Name)); err != nil {
			return err
		}
	}
	return ctx.Err()
}
