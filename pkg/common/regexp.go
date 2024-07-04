package common

import (
	"fmt"
	"regexp"
)

func NewRegexp(plain string) (Regexp, error) {
	var buf Regexp
	if err := buf.Set(plain); err != nil {
		return Regexp{}, nil
	}
	return buf, nil
}

func MustNewRegexp(plain string) Regexp {
	buf, err := NewRegexp(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type Regexp struct {
	v *regexp.Regexp
}

func (this Regexp) IsZero() bool {
	return this.v == nil
}

func (this Regexp) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this Regexp) String() string {
	if v := this.v; v != nil {
		return v.String()
	}
	return ""
}

func (this *Regexp) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		this.v = nil
		return nil
	}

	v, err := regexp.Compile(string(text))
	if err != nil {
		return fmt.Errorf("illegal regex")
	}

	this.v = v
	return nil
}

func (this *Regexp) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this *Regexp) MatchString(s string) bool {
	if v := this.v; v != nil {
		return v.MatchString(s)
	}
	return false
}
