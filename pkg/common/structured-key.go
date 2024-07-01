package common

import (
	"strconv"
	"strings"
)

func StructuredKeyOf(args ...string) StructuredKey {
	return args
}

type StructuredKey []string

func (this StructuredKey) String() string {
	return strings.Join(this, ".")
}

func (this StructuredKey) Child(key string) StructuredKey {
	return append(this, key)
}

func (this StructuredKey) Index(i int) StructuredKey {
	return this.Child(strconv.Itoa(i))
}
