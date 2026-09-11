package crypto

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type KnownHosts string

func (this KnownHosts) Validate() error {
	if this.IsZero() {
		return nil
	}
	return validateKnownHosts([]byte(this))
}

func (this KnownHosts) IsZero() bool {
	return strings.TrimSpace(string(this)) == ""
}

func (this *KnownHosts) Trim() error {
	*this = KnownHosts(strings.TrimSpace(string(*this)))
	return nil
}

func (this KnownHosts) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case KnownHosts:
		return this == v
	case *KnownHosts:
		return v != nil && this == *v
	default:
		return false
	}
}

type KnownHostsFile string

func (this KnownHostsFile) Validate() error {
	if this.IsZero() {
		return nil
	}
	raw, err := os.ReadFile(string(this))
	if err != nil {
		return fmt.Errorf("cannot read known hosts file %q: %w", this, err)
	}
	return validateKnownHosts(raw)
}

func (this KnownHostsFile) IsZero() bool {
	return strings.TrimSpace(string(this)) == ""
}

func (this *KnownHostsFile) Trim() error {
	*this = KnownHostsFile(strings.TrimSpace(string(*this)))
	return nil
}

func (this KnownHostsFile) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case KnownHostsFile:
		return this == v
	case *KnownHostsFile:
		return v != nil && this == *v
	default:
		return false
	}
}

func validateKnownHosts(raw []byte) error {
	remaining := raw
	found := false
	for len(remaining) > 0 {
		marker, _, key, _, rest, err := ssh.ParseKnownHosts(remaining)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("illegal known hosts: %w", err)
		}
		if marker != "" && marker != "revoked" && marker != "cert-authority" {
			return fmt.Errorf("illegal known hosts marker @%s", marker)
		}
		if key != nil {
			found = true
		}
		if len(rest) >= len(remaining) {
			return fmt.Errorf("illegal known hosts: parser made no progress")
		}
		remaining = rest
	}
	if !found {
		return fmt.Errorf("illegal or non-existent known hosts")
	}
	f, err := os.CreateTemp("", "bifroest-known-hosts-validation-*")
	if err != nil {
		return fmt.Errorf("cannot create temporary known hosts validation file: %w", err)
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return fmt.Errorf("cannot write temporary known hosts validation file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("cannot close temporary known hosts validation file: %w", err)
	}
	if _, err := knownhosts.New(name); err != nil {
		return fmt.Errorf("illegal known hosts: %w", err)
	}
	return nil
}

func NewKnownHostsCallback(inline KnownHosts, file KnownHostsFile) (ssh.HostKeyCallback, error) {
	if err := inline.Validate(); err != nil {
		return nil, err
	}
	if err := file.Validate(); err != nil {
		return nil, err
	}

	var files []string
	if !inline.IsZero() {
		f, err := os.CreateTemp("", "bifroest-known-hosts-*")
		if err != nil {
			return nil, fmt.Errorf("cannot create temporary known hosts file: %w", err)
		}
		name := f.Name()
		defer func() { _ = os.Remove(name) }()
		if _, err := f.WriteString(string(inline)); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("cannot write temporary known hosts file: %w", err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("cannot close temporary known hosts file: %w", err)
		}
		files = append(files, name)
	}
	if !file.IsZero() {
		files = append(files, string(file))
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no known hosts configured")
	}
	callback, err := knownhosts.New(files...)
	if err != nil {
		return nil, fmt.Errorf("cannot load known hosts: %w", err)
	}
	return callback, nil
}
