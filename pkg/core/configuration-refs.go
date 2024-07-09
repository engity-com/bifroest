package core

import (
	"bytes"
	"fmt"
	"strings"
)

type ConfigurationRefs struct {
	v map[ConfigurationKey]*ConfigurationRef
}

func (this ConfigurationRefs) IsZero() bool {
	return this.v == nil || len(this.v) == 0
}

func (this ConfigurationRefs) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this ConfigurationRefs) String() string {
	if this.v == nil {
		return ""
	}
	strs := make([]string, len(this.v))
	var i int
	for k, v := range this.v {
		if k == DefaultConfigurationKey {
			strs[i] = v.String()
		} else {
			strs[i] = k.String() + ":" + v.String()
		}
		i++
	}
	return strings.Join(strs, ",")
}

func (this *ConfigurationRefs) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return fmt.Errorf("empty configuration reference")
	}

	if this.v == nil {
		this.v = map[ConfigurationKey]*ConfigurationRef{}
	}

	for i, plain := range bytes.Split(text, []byte(",")) {
		plain = bytes.TrimSpace(plain)
		if len(plain) == 0 {
			return fmt.Errorf("[%d] empty configuration reference", i)
		}
		plainKv := bytes.SplitN(plain, []byte(":"), 2)
		var plainK, plainV []byte
		if len(plainKv) >= 2 {
			plainK = plainKv[0]
			plainV = plainKv[1]
		} else {
			plainK = []byte(DefaultConfigurationKey)
			plainV = plainKv[0]
		}

		var key ConfigurationKey
		var ref ConfigurationRef

		if err := key.UnmarshalText(plainK); err != nil {
			return fmt.Errorf("[%d] %w", i, err)
		}
		if err := ref.UnmarshalText(plainV); err != nil {
			return fmt.Errorf("[%d] %w", i, err)
		}

		this.v[key] = &ref
	}

	return nil
}

func (this *ConfigurationRefs) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this ConfigurationRefs) IsCumulative() bool {
	return true
}

func (this ConfigurationRefs) getOrNil(in *ConfigurationRef) *Configuration {
	if in == nil {
		return nil
	}
	return in.Get()
}

func (this ConfigurationRefs) Get(k ConfigurationKey) (*Configuration, error) {
	if k.IsZero() {
		k = DefaultConfigurationKey
	}
	if this.v == nil {
		return nil, nil
	}
	if v := this.v[k]; v != nil {
		return this.getOrNil(v), nil
	}
	return nil, nil
}

func (this ConfigurationRefs) GetKeys() ([]ConfigurationKey, error) {
	if this.v == nil {
		return nil, nil
	}
	results := make([]ConfigurationKey, len(this.v))
	var i int
	for k := range this.v {
		results[i] = k
	}
	return results, nil
}
