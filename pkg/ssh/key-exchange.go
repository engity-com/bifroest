package ssh

import (
	"bytes"
	"fmt"
	"slices"
)

type KeyExchange uint8

const (
	KeyExchangeDh1Sha1 KeyExchange = iota
	KeyExchangeDh14Sha1
	KeyExchangeDh14Sha256
	KeyExchangeDh16Sha512
	KeyExchangeEcdh256
	KeyExchangeEcdh384
	KeyExchangeEcdh521
	KeyExchangeCurve25519Sha256LibSsh
	KeyExchangeCurve25519Sha256
	KeyExchangeDhgexSha1
	KeyExchangeDhgexSha256
)

var (
	keyExchange2Name = map[KeyExchange]string{
		KeyExchangeDh1Sha1:                "diffie-hellman-group1-sha1",
		KeyExchangeDh14Sha1:               "diffie-hellman-group14-sha1",
		KeyExchangeDh14Sha256:             "diffie-hellman-group14-sha256",
		KeyExchangeDh16Sha512:             "diffie-hellman-group16-sha512",
		KeyExchangeEcdh256:                "ecdh-sha2-nistp256",
		KeyExchangeEcdh384:                "ecdh-sha2-nistp384",
		KeyExchangeEcdh521:                "ecdh-sha2-nistp521",
		KeyExchangeCurve25519Sha256LibSsh: "curve25519-sha256@libssh.org",
		KeyExchangeCurve25519Sha256:       "curve25519-sha256",
		KeyExchangeDhgexSha1:              "diffie-hellman-group-exchange-sha1",
		KeyExchangeDhgexSha256:            "diffie-hellman-group-exchange-sha256",
	}
	name2KeyExchange = func(in map[KeyExchange]string) map[string]KeyExchange {
		result := make(map[string]KeyExchange, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(keyExchange2Name)

	DefaultKeyExchanges = []KeyExchange{
		KeyExchangeCurve25519Sha256LibSsh,
		KeyExchangeCurve25519Sha256,
		KeyExchangeDh16Sha512,
		KeyExchangeDh14Sha256,
	}
)

func (this KeyExchange) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this KeyExchange) MarshalText() (text []byte, err error) {
	if v, ok := keyExchange2Name[this]; ok {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("illegal ssh key exchange: %d", this)
}

func (this KeyExchange) String() string {
	if v, err := this.MarshalText(); err == nil {
		return string(v)
	}
	return fmt.Sprintf("illegal-ssh-key-exchange-%d", this)
}

func (this *KeyExchange) UnmarshalText(text []byte) error {
	if v, ok := name2KeyExchange[string(text)]; ok {
		*this = v
		return nil
	}
	return fmt.Errorf("illegal ssh key exchange: %q", string(text))
}

func (this *KeyExchange) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this KeyExchange) IsZero() bool {
	return false
}

func (this KeyExchange) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case KeyExchange:
		return this.isEqualTo(&v)
	case *KeyExchange:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this KeyExchange) isEqualTo(other *KeyExchange) bool {
	return this == *other
}

type KeyExchanges []KeyExchange

func (this KeyExchanges) IsEmpty() bool {
	return len(this) == 0
}

func (this KeyExchanges) IsCumulative() bool {
	return true
}

func (this KeyExchanges) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this KeyExchanges) MarshalTexts() (texts [][]byte, err error) {
	texts = make([][]byte, len(this))
	for i, v := range this {
		texts[i], err = v.MarshalText()
		if err != nil {
			return nil, fmt.Errorf("[%d] %w", i, err)
		}
	}
	return texts, nil
}
func (this KeyExchanges) MarshalText() (text []byte, err error) {
	texts, err := this.MarshalTexts()
	if err != nil {
		return nil, err
	}
	return bytes.Join(texts, []byte(",")), nil
}

func (this KeyExchanges) String() string {
	v, err := this.MarshalText()
	if err != nil {
		return fmt.Sprintf("illegal-ssh-key-exchanges: %s", err.Error())
	}
	return string(v)
}

func (this *KeyExchanges) UnmarshalText(text []byte) error {
	texts := bytes.Split(text, []byte(","))
	for _, v := range texts {
		var buf KeyExchange
		if err := buf.UnmarshalText(v); err != nil {
			return err
		}
		*this = append(*this, buf)
	}
	return nil
}

func (this *KeyExchanges) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this KeyExchanges) IsZero() bool {
	return false
}

func (this KeyExchanges) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case KeyExchanges:
		return this.isEqualTo(&v)
	case *KeyExchanges:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this KeyExchanges) isEqualTo(other *KeyExchanges) bool {
	if len(this) != len(*other) {
		return false
	}
	for i, tv := range this {
		ov := (*other)[i]
		if !tv.isEqualTo(&ov) {
			return false
		}
	}
	return true
}

func (this KeyExchanges) Contains(v KeyExchange) bool {
	return slices.Contains(this, v)
}
