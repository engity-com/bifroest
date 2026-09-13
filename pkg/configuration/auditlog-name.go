package configuration

import (
	"fmt"
	"strings"
)

const (
	DefaultAuditlogName       AuditlogName = "default"
	maximumAuditlogNameLength int          = 128
)

type AuditlogName string

func (this AuditlogName) IsZero() bool {
	return len(this) == 0
}

func (this AuditlogName) MarshalText() ([]byte, error) {
	return []byte(this.String()), nil
}

func (this AuditlogName) String() string {
	return string(this)
}

func (this *AuditlogName) UnmarshalText(text []byte) error {
	value := AuditlogName(text)
	if err := value.Validate(); err != nil {
		return err
	}
	*this = value
	return nil
}

func (this *AuditlogName) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this AuditlogName) Validate() error {
	if len(this) == 0 || this == "." || this == ".." {
		return fmt.Errorf("illegal auditlog name: %q", this)
	}
	if len(this) > maximumAuditlogNameLength {
		return fmt.Errorf("auditlog name exceeds %d bytes", maximumAuditlogNameLength)
	}
	for _, character := range string(this) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '.' {
			continue
		}
		return fmt.Errorf("illegal auditlog name: %q", this)
	}
	return nil
}

func (this AuditlogName) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch value := other.(type) {
	case string:
		return string(this) == value
	case *string:
		return value != nil && string(this) == *value
	case AuditlogName:
		return this == value
	case *AuditlogName:
		return value != nil && this == *value
	default:
		return false
	}
}

func (this AuditlogName) Clone() AuditlogName {
	return AuditlogName(strings.Clone(string(this)))
}
