package service

import (
	"fmt"
	"os"
	"strings"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type httpRuntimePath struct{ path, description string }

// This runs on the cloned candidate, before opening files or creating state.
// Canonical aliases and existing hard links must not expose private inputs via
// future public overlays or mutable session/audit/ACME storage.
func validateHTTPRuntimePaths(conf *configuration.Configuration, storage string) error {
	if !conf.Http.IsEnabled() {
		return nil
	}
	h := conf.Http
	var private, public []httpRuntimePath
	resolve := func(path, description string) (httpRuntimePath, error) {
		resolved, err := sys.CanonicalPath(path)
		if err != nil {
			return httpRuntimePath{}, errors.Config.Newf("cannot resolve %s (details redacted)", description)
		}
		return httpRuntimePath{resolved, description}, nil
	}
	add := func(target *[]httpRuntimePath, path, description string) error {
		if path == "" {
			return nil
		}
		value, err := resolve(path, description)
		if err != nil {
			return err
		}
		*target = append(*target, value)
		return nil
	}
	if err := add(&private, storage, "session storage"); err != nil {
		return err
	}
	for _, auditlog := range conf.Auditlogs {
		if err := add(&private, auditlog.IdentityFile, fmt.Sprintf("auditlog %q identity file", auditlog.Name)); err != nil {
			return err
		}
		if err := add(&private, auditlog.Directory, fmt.Sprintf("auditlog %q journal", auditlog.Name)); err != nil {
			return err
		}
		if err := add(&private, auditlog.Recording.Directory, fmt.Sprintf("auditlog %q recording directory", auditlog.Name)); err != nil {
			return err
		}
		if err := add(&private, string(auditlog.EncryptionPublicKeyFile), fmt.Sprintf("auditlog %q recipient file", auditlog.Name)); err != nil {
			return err
		}
		targets := append(configuration.AuditlogTargets(nil), auditlog.Targets...)
		targets = append(targets, auditlog.Recording.Targets.Configured()...)
		for _, target := range targets {
			if sftp, ok := target.V.(*configuration.AuditlogTargetSftp); ok && sftp != nil {
				if err := add(&private, string(sftp.KnownHostsFile), "SFTP known hosts file"); err != nil {
					return err
				}
				for _, path := range sftp.IdentityFiles {
					if err := add(&private, path, "SFTP identity file"); err != nil {
						return err
					}
				}
			}
		}
	}
	hostKeys, err := conf.Ssh.Keys.HostKeys.Render(noopContext{})
	if err != nil {
		return errors.Config.Newf("cannot render SSH host key paths")
	}
	for _, path := range hostKeys {
		if err := add(&private, path, "SSH host key"); err != nil {
			return err
		}
	}
	for _, flow := range conf.Flows {
		ssh, ok := flow.Environment.V.(*configuration.EnvironmentSsh)
		if !ok || ssh == nil {
			continue
		}
		if err := add(&private, string(ssh.KnownHostsFile), "SSH known hosts file"); err != nil {
			return err
		}
		if certificate := ssh.Certificate; certificate != nil {
			for _, path := range []string{certificate.IdentityFile.String(), certificate.AuthorityIdentityFile.String()} {
				if err := add(&private, strings.TrimSpace(path), "SSH certificate key"); err != nil {
					return err
				}
			}
		} else {
			for _, path := range ssh.IdentityFiles {
				if path.IsHardCoded() {
					if err := add(&private, strings.TrimSpace(path.String()), "static SSH identity file"); err != nil {
						return err
					}
				}
			}
		}
	}
	check := func(value httpRuntimePath, others []httpRuntimePath) error {
		for _, other := range others {
			if httpRuntimePathsOverlap(value.path, other.path) {
				return errors.Config.Newf("%s overlaps %s", value.description, other.description)
			}
		}
		return nil
	}
	var tlsPaths []httpRuntimePath
	for i := range h.Tls.Certificates {
		pair := &h.Tls.Certificates[i]
		for _, field := range []struct {
			value       *string
			description string
		}{
			{&pair.CertificateFile, "HTTPS certificate file"}, {&pair.PrivateKeyFile, "HTTPS private key file"},
		} {
			value, err := resolve(*field.value, field.description)
			if err != nil {
				return err
			}
			if err := check(value, private); err != nil {
				return err
			}
			*field.value = value.path
			tlsPaths = append(tlsPaths, value)
		}
	}
	private = append(private, tlsPaths...)
	if h.Tls.Acme.Enabled {
		value, err := resolve(h.Tls.Acme.Storage, "HTTPS ACME storage")
		if err != nil {
			return err
		}
		if err := check(value, private); err != nil {
			return err
		}
		h.Tls.Acme.Storage = value.path
		private = append(private, value)
	}
	if h.AssetsDirectory != "" {
		value, err := resolve(h.AssetsDirectory, "HTTP asset directory")
		if err != nil {
			return err
		}
		h.AssetsDirectory = value.path
		public = append(public, value)
	}
	for _, files := range []configuration.HttpAssetFiles{h.CustomCss, h.CustomJs} {
		for i := range files {
			value, err := resolve(files[i], "HTTP customization file")
			if err != nil {
				return err
			}
			files[i] = value.path
			public = append(public, value)
		}
	}
	for _, value := range public {
		if err := check(value, private); err != nil {
			return err
		}
	}
	return nil
}

func httpRuntimePathsOverlap(a, b string) bool {
	if runtimePathsOverlap(a, b) {
		return true
	}
	left, errA := os.Stat(a)
	right, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(left, right)
}
