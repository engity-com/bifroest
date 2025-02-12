package ssh

import (
	"bytes"
	"fmt"
	"slices"
)

type Cipher uint8

const (
	CipherAes128Cbc Cipher = iota
	Cipher3desCbc
	CipherArcfour
	CipherArcfour128
	CipherArcfour256
	CipherChacha20Poly1305
	CipherAes128Ctr
	CipherAes192Ctr
	CipherAes256Ctr
	CipherAes128Gcm
	CipherAes256Gcm
)

var (
	cipher2Name = map[Cipher]string{
		CipherAes128Cbc:        "aes128-cbc",
		Cipher3desCbc:          "3des-cbc",
		CipherArcfour:          "arcfour",
		CipherArcfour128:       "arcfour128",
		CipherArcfour256:       "arcfour256",
		CipherChacha20Poly1305: "chacha20-poly1305@openssh.com",
		CipherAes128Ctr:        "aes128-ctr",
		CipherAes192Ctr:        "aes192-ctr",
		CipherAes256Ctr:        "aes256-ctr",
		CipherAes128Gcm:        "aes128-gcm@openssh.com",
		CipherAes256Gcm:        "aes256-gcm@openssh.com",
	}
	name2Cipher = func(in map[Cipher]string) map[string]Cipher {
		result := make(map[string]Cipher, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(cipher2Name)

	DefaultCiphers = []Cipher{
		CipherAes256Gcm,
		CipherAes256Ctr,
		CipherAes192Ctr,
	}
)

func (this Cipher) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this Cipher) MarshalText() (text []byte, err error) {
	if v, ok := cipher2Name[this]; ok {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("illegal ssh cipher: %d", this)
}

func (this Cipher) String() string {
	if v, err := this.MarshalText(); err == nil {
		return string(v)
	}
	return fmt.Sprintf("illegal-ssh-cipher-%d", this)
}

func (this *Cipher) UnmarshalText(text []byte) error {
	if v, ok := name2Cipher[string(text)]; ok {
		*this = v
		return nil
	}
	return fmt.Errorf("illegal ssh cipher: %q", string(text))
}

func (this *Cipher) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this Cipher) IsZero() bool {
	return false
}

func (this Cipher) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Cipher:
		return this.isEqualTo(&v)
	case *Cipher:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Cipher) isEqualTo(other *Cipher) bool {
	return this == *other
}

type Ciphers []Cipher

func (this Ciphers) IsEmpty() bool {
	return len(this) == 0
}

func (this Ciphers) IsCumulative() bool {
	return true
}

func (this Ciphers) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this Ciphers) MarshalTexts() (texts [][]byte, err error) {
	texts = make([][]byte, len(this))
	for i, v := range this {
		texts[i], err = v.MarshalText()
		if err != nil {
			return nil, fmt.Errorf("[%d] %w", i, err)
		}
	}
	return texts, nil
}
func (this Ciphers) MarshalText() (text []byte, err error) {
	texts, err := this.MarshalTexts()
	if err != nil {
		return nil, err
	}
	return bytes.Join(texts, []byte(",")), nil
}

func (this Ciphers) String() string {
	v, err := this.MarshalText()
	if err != nil {
		return fmt.Sprintf("illegal-ssh-ciphers: %s", err.Error())
	}
	return string(v)
}

func (this *Ciphers) UnmarshalText(text []byte) error {
	texts := bytes.Split(text, []byte(","))
	for _, v := range texts {
		var buf Cipher
		if err := buf.UnmarshalText(v); err != nil {
			return err
		}
		*this = append(*this, buf)
	}
	return nil
}

func (this *Ciphers) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this Ciphers) IsZero() bool {
	return false
}

func (this Ciphers) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Ciphers:
		return this.isEqualTo(&v)
	case *Ciphers:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Ciphers) isEqualTo(other *Ciphers) bool {
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

func (this Ciphers) Contains(v Cipher) bool {
	return slices.Contains(this, v)
}
