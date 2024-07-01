package sys

import (
	"fmt"
	"strings"
)

type EnvVars map[string]string

func (this *EnvVars) Add(in ...string) {
	if *this == nil {
		*this = EnvVars{}
	}
	for _, line := range in {
		this.add(line)
	}
}

func (this *EnvVars) add(in string) {
	if *this == nil {
		*this = EnvVars{}
	}
	kv := strings.SplitN(in, "=", 2)
	if len(kv) == 1 {
		(*this)[kv[0]] = ""
	} else {
		(*this)[kv[0]] = kv[1]
	}
}

func (this *EnvVars) Set(kOrV ...string) {
	if len(kOrV)%2 != 0 {
		//goland:noinspection GoErrorStringFormat
		panic(fmt.Errorf("Set(..) should be called with an even number of arguments, but got: %d", len(kOrV)))
	}
	l := len(kOrV)
	for i := 0; i < l; i += 2 {
		this.set(kOrV[i], kOrV[i+1])
	}
}

func (this *EnvVars) set(k, v string) {
	if *this == nil {
		*this = EnvVars{}
	}
	(*this)[k] = v
}

func (this *EnvVars) AddAllOf(in EnvVars) {
	if in == nil {
		return
	}
	if *this == nil {
		*this = EnvVars{}
	}
	for k, v := range in {
		(*this)[k] = v
	}
}

func (this *EnvVars) Strings() []string {
	if *this == nil {
		return nil
	}
	result := make([]string, len(*this))
	var i int
	for k, v := range *this {
		result[i] = k + "=" + v
		i++
	}
	return result
}

func (this *EnvVars) String() string {
	return strings.Join(this.Strings(), "\n")
}

func (this EnvVars) Clone() EnvVars {
	if this == nil {
		return nil
	}
	result := make(EnvVars, len(this))
	for k, v := range this {
		result[k] = v
	}
	return result
}
