package configuration

import (
	"fmt"
	"strings"
)

const maximumAuditlogTargetNameLength = 128

// AuditlogTargetName identifies one remote target within an auditlog. Its text
// form is safe to use as a path component for future delivery state.
type AuditlogTargetName string

func (this AuditlogTargetName) IsZero() bool {
	return len(this) == 0
}

func (this AuditlogTargetName) MarshalText() ([]byte, error) {
	return []byte(this.String()), nil
}

func (this AuditlogTargetName) String() string {
	return string(this)
}

func (this *AuditlogTargetName) UnmarshalText(text []byte) error {
	value := AuditlogTargetName(text)
	if err := value.Validate(); err != nil {
		return err
	}
	*this = value
	return nil
}

func (this *AuditlogTargetName) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this AuditlogTargetName) Validate() error {
	if len(this) == 0 || this == "." || this == ".." {
		return fmt.Errorf("illegal auditlog target name: %q", this)
	}
	if len(this) > maximumAuditlogTargetNameLength {
		return fmt.Errorf("auditlog target name exceeds %d bytes", maximumAuditlogTargetNameLength)
	}
	for _, character := range string(this) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '.' {
			continue
		}
		return fmt.Errorf("illegal auditlog target name: %q", this)
	}
	return nil
}

func (this AuditlogTargetName) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch value := other.(type) {
	case string:
		return string(this) == value
	case *string:
		return value != nil && string(this) == *value
	case AuditlogTargetName:
		return this == value
	case *AuditlogTargetName:
		return value != nil && this == *value
	default:
		return false
	}
}

func (this AuditlogTargetName) Clone() AuditlogTargetName {
	return AuditlogTargetName(strings.Clone(string(this)))
}
