package configuration

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/errors"
)

type PullPolicy uint8

const (
	PullPolicyIfAbsent PullPolicy = iota
	PullPolicyAlways
)

var (
	pullPolicyToName = map[PullPolicy]string{
		PullPolicyIfAbsent: "ifAbsent",
		PullPolicyAlways:   "always",
	}
	nameToPullPolicy = func(in map[PullPolicy]string) map[string]PullPolicy {
		result := make(map[string]PullPolicy, len(in))
		for k, v := range in {
			result[v] = k
		}
		result[""] = PullPolicyIfAbsent
		result["if-absent"] = PullPolicyIfAbsent
		return result
	}(pullPolicyToName)
)

func (this PullPolicy) IsZero() bool {
	return false
}

func (this PullPolicy) MarshalText() (text []byte, err error) {
	v, ok := pullPolicyToName[this]
	if !ok {
		return nil, errors.Config.Newf("illegal pull-policy: %d", this)
	}
	return []byte(v), nil
}

func (this PullPolicy) String() string {
	v, ok := pullPolicyToName[this]
	if !ok {
		return fmt.Sprintf("illegal-pull-policy-%d", this)
	}
	return v
}

func (this *PullPolicy) UnmarshalText(text []byte) error {
	v, ok := nameToPullPolicy[string(text)]
	if !ok {
		return errors.Config.Newf("illegal pull-policy: %s", string(text))
	}
	*this = v
	return nil
}

func (this *PullPolicy) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this PullPolicy) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this PullPolicy) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case PullPolicy:
		return this.isEqualTo(&v)
	case *PullPolicy:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this PullPolicy) isEqualTo(other *PullPolicy) bool {
	return this == *other
}

func (this PullPolicy) Clone() PullPolicy {
	return this
}
