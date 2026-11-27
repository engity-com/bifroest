package configuration

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// TlsDefinitions contains named definitions, never reference chains.
// Defining TLS performs no I/O.
type TlsDefinitions map[string]Tls

func (this *TlsDefinitions) SetDefaults() error { *this = nil; return nil }
func (this *TlsDefinitions) Trim() error {
	for _, name := range definitionKeys(*this) {
		value := (*this)[name]
		if err := value.Trim(); err != nil {
			return fmt.Errorf("[%s] %w", name, err)
		}
		(*this)[name] = value
	}
	return this.Validate()
}
func (this TlsDefinitions) Validate() error {
	seen := make(map[string]bool)
	for name := range this {
		// Default stores use the name as a directory component on every OS.
		// Reject portable-path aliases before any store can be created.
		if err := validateTlsName(name); err != nil {
			return err
		}
		folded := strings.ToLower(name)
		if seen[folded] {
			return fmt.Errorf("TLS names must also be unique ignoring case")
		}
		seen[folded] = true
	}
	return validateDefinitions(this, func(value *Tls) error {
		if value.Reference != "" || value.definition != nil {
			return fmt.Errorf("must be an inline TLS definition, not a reference")
		}
		return value.Validate()
	})
}

func validateTlsName(name string) error {
	if name == "" || name == "." || name == ".." || strings.HasSuffix(name, ".") {
		return fmt.Errorf("invalid TLS name")
	}
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._-", character) {
			continue
		}
		return fmt.Errorf("TLS name must use ASCII letters, digits, dots, underscores or hyphens")
	}
	base, _, _ := strings.Cut(strings.ToUpper(name), ".")
	if slices.Contains([]string{"CON", "PRN", "AUX", "NUL"}, base) ||
		len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return fmt.Errorf("TLS name is reserved by an operating system")
	}
	return nil
}
func (this *TlsDefinitions) UnmarshalYAML(node *yaml.Node) error {
	if err := decodeDefinitions(node, this); err != nil {
		return err
	}
	fields, err := effectiveHttpFields(node)
	if err != nil {
		return err
	}
	// Every named definition has its own store. A name cannot escape the state directory.
	for name, value := range *this {
		entry := fields[name]
		storage := filepath.Join(filepath.Dir(filepath.Dir(DefaultHttpAcmeStorage)), "tls", name, "acme")
		if err := value.setDefaultAcmeStorage(&entry, storage); err != nil {
			return err
		}
		(*this)[name] = value
	}
	return this.Validate()
}

func (this *Tls) setDefaultAcmeStorage(node *yaml.Node, storage string) error {
	if this == nil || this.Reference != "" || !this.Acme.IsEnabled() {
		return nil
	}
	fields, err := effectiveHttpFields(node)
	if err != nil {
		return err
	}
	acmeFields := map[string]yaml.Node{}
	if node, exists := fields["acme"]; exists {
		acmeFields, err = effectiveHttpFields(&node)
		if err != nil {
			return err
		}
	}
	if _, explicit := acmeFields["storage"]; !explicit {
		this.Acme.Storage = storage
	}
	return nil
}
func (this TlsDefinitions) IsEqualTo(other any) bool {
	switch other := other.(type) {
	case TlsDefinitions:
		return maps.EqualFunc(this, other, func(left, right Tls) bool { return left.IsEqualTo(right) })
	case *TlsDefinitions:
		return other != nil && this.IsEqualTo(*other)
	default:
		return false
	}
}

func (this *Configuration) resolveTlsReferences() error {
	if err := this.Tls.Validate(); err != nil {
		return fmt.Errorf("[tls] %w", err)
	}
	resolve := func(reference string, target **Tls) error {
		*target = nil
		if reference == "" {
			return nil
		}
		profile, exists := this.Tls[reference]
		if !exists {
			return fmt.Errorf("references unknown TLS definition %q", reference)
		}
		profile = cloneConfigurationValue(profile)
		*target = &profile
		return nil
	}
	// An automatic selection is optional; a named reference is not. Keep that
	// distinction when definitions change and Validate resolves them again.
	selectDefault := func(target **Tls) {
		if _, exists := this.Tls["default"]; exists {
			*target = &Tls{Reference: "default", implicit: true}
		} else {
			*target = nil
		}
	}
	if h := this.Http; h != nil {
		if h.Tls == nil && !h.tlsExplicitNull || h.Tls != nil && h.Tls.implicit {
			selectDefault(&h.Tls)
		} else if h.Tls != nil {
			h.tlsExplicitNull = false
		}
		if h.Tls != nil {
			if err := resolve(h.Tls.Reference, &h.Tls.definition); err != nil {
				return fmt.Errorf("[http][tls] %w", err)
			}
		}
	}
	if m := this.Monitoring; m != nil {
		if m.Tls == nil && m.tlsDefault || m.Tls != nil && m.Tls.implicit {
			m.tlsDefault = true
			selectDefault(&m.Tls)
		} else if m.Tls != nil {
			m.tlsDefault = false
		}
		if m.Tls != nil {
			if err := resolve(m.Tls.Reference, &m.Tls.definition); err != nil {
				return fmt.Errorf("[monitoring][tls] %w", err)
			}
		}
	}
	return nil
}

func (this *Configuration) validateTlsListener() error {
	acme := false
	if this.Http.IsListenerEnabled() && this.Http.Tls.IsEnabled() {
		definition, err := this.Http.Tls.ServerDefinition()
		if err != nil {
			return fmt.Errorf("[http][tls] %w", err)
		}
		acme = definition.Acme.IsEnabled()
	}
	if this.Monitoring.IsEnabled() && this.Monitoring.Tls.IsEnabled() {
		definition, err := this.Monitoring.Tls.ServerDefinition()
		if err != nil {
			return fmt.Errorf("[monitoring][tls] %w", err)
		}
		acme = acme || definition.Acme.IsEnabled()
	}
	if acme && (!this.Http.IsListenerEnabled() || !this.Http.Tls.IsEnabled()) {
		return fmt.Errorf("[http] active ACME requires a TLS listener with enabled true or acmeTlsAlpnOnly")
	}
	return nil
}
