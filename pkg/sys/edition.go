package sys

import (
	"fmt"
	"slices"
	"strings"
)

type Edition uint8

const (
	EditionUnknown Edition = iota
	EditionGeneric
	EditionExtended
)

func (this Edition) String() string {
	v, ok := editionToName[this]
	if !ok {
		return fmt.Sprintf("illegal-edition-%d", this)
	}
	return v
}

func (this Edition) MarshalText() ([]byte, error) {
	v, ok := editionToName[this]
	if !ok {
		return nil, fmt.Errorf("illegal-edition: %d", this)
	}
	return []byte(v), nil
}

func (this *Edition) UnmarshalText(in []byte) error {
	if len(in) == 0 {
		*this = EditionGeneric
		return nil
	}
	v, ok := stringToEdition[string(in)]
	if !ok {
		return fmt.Errorf("illegal-edition: %s", string(in))
	}
	*this = v
	return nil
}

func (this *Edition) Set(plain string) error {
	return this.UnmarshalText([]byte(plain))
}

func (this Edition) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this Edition) IsZero() bool {
	return this == 0
}

type Editions []Edition

func (this Editions) String() string {
	return strings.Join(this.Strings(), ",")
}

func (this Editions) Strings() []string {
	strs := make([]string, len(this))
	for i, v := range this {
		strs[i] = v.String()
	}
	return strs
}

func (this *Editions) Set(plain string) error {
	parts := strings.Split(plain, ",")
	buf := make(Editions, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if err := buf[i].Set(part); err != nil {
			return err
		}
	}
	*this = buf
	return nil
}

func AllEditionVariants() Editions {
	return slices.Clone(allEditionVariants)
}

var (
	editionToName = map[Edition]string{
		EditionExtended: "extended",
		EditionGeneric:  "generic",
	}
	stringToEdition = func(in map[Edition]string) map[string]Edition {
		result := make(map[string]Edition, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(editionToName)
	allEditionVariants = func(in map[Edition]string) Editions {
		result := make([]Edition, len(in))
		var i int
		for k := range in {
			result[i] = k
			i++
		}
		return result
	}(editionToName)
)
