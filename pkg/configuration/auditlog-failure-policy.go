package configuration

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/errors"
)

type AuditlogFailurePolicy uint8

const (
	AuditlogFailurePolicyStrict AuditlogFailurePolicy = iota
	AuditlogFailurePolicyBestEffort
)

var (
	auditlogFailurePolicyToName = map[AuditlogFailurePolicy]string{
		AuditlogFailurePolicyStrict:     "strict",
		AuditlogFailurePolicyBestEffort: "bestEffort",
	}
	nameToAuditlogFailurePolicy = func(in map[AuditlogFailurePolicy]string) map[string]AuditlogFailurePolicy {
		result := make(map[string]AuditlogFailurePolicy, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(auditlogFailurePolicyToName)
)

func (this AuditlogFailurePolicy) IsZero() bool {
	return false
}

func (this AuditlogFailurePolicy) MarshalText() ([]byte, error) {
	value, ok := auditlogFailurePolicyToName[this]
	if !ok {
		return nil, errors.Config.Newf("illegal auditlog failure policy: %d", this)
	}
	return []byte(value), nil
}

func (this AuditlogFailurePolicy) String() string {
	value, ok := auditlogFailurePolicyToName[this]
	if !ok {
		return fmt.Sprintf("illegal-auditlog-failure-policy-%d", this)
	}
	return value
}

func (this *AuditlogFailurePolicy) UnmarshalText(text []byte) error {
	value, ok := nameToAuditlogFailurePolicy[string(text)]
	if !ok {
		return errors.Config.Newf("illegal auditlog failure policy: %s", string(text))
	}
	*this = value
	return nil
}

func (this *AuditlogFailurePolicy) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this AuditlogFailurePolicy) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this AuditlogFailurePolicy) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch value := other.(type) {
	case AuditlogFailurePolicy:
		return this == value
	case *AuditlogFailurePolicy:
		return value != nil && this == *value
	default:
		return false
	}
}

func (this AuditlogFailurePolicy) Clone() AuditlogFailurePolicy {
	return this
}
