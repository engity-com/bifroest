package ssh

import (
	"bytes"
	"fmt"
	"slices"
)

type MessageAuthentication uint8

const (
	MessageAuthenticationHmacSha1 MessageAuthentication = iota
	MessageAuthenticationHmacSha1B96
	MessageAuthenticationHmacSha2B256
	MessageAuthenticationHmacSha2B512
	MessageAuthenticationHmacSha2B256Etm
	MessageAuthenticationHmacSha2B512Etm
)

var (
	messageAuthentication2Name = map[MessageAuthentication]string{
		MessageAuthenticationHmacSha1:        "hmac-sha1",
		MessageAuthenticationHmacSha1B96:     "hmac-sha1-96",
		MessageAuthenticationHmacSha2B256:    "hmac-sha2-256",
		MessageAuthenticationHmacSha2B512:    "hmac-sha2-512",
		MessageAuthenticationHmacSha2B256Etm: "hmac-sha2-256-etm@openssh.com",
		MessageAuthenticationHmacSha2B512Etm: "hmac-sha2-512-etm@openssh.com",
	}
	name2MessageAuthentication = func(in map[MessageAuthentication]string) map[string]MessageAuthentication {
		result := make(map[string]MessageAuthentication, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(messageAuthentication2Name)

	DefaultMessageAuthentications = []MessageAuthentication{
		MessageAuthenticationHmacSha2B512Etm,
		MessageAuthenticationHmacSha2B256Etm,
	}
)

func (this MessageAuthentication) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this MessageAuthentication) MarshalText() (text []byte, err error) {
	if v, ok := messageAuthentication2Name[this]; ok {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("illegal ssh message authentication: %d", this)
}

func (this MessageAuthentication) String() string {
	if v, err := this.MarshalText(); err == nil {
		return string(v)
	}
	return fmt.Sprintf("illegal-ssh-message-authentication-%d", this)
}

func (this *MessageAuthentication) UnmarshalText(text []byte) error {
	if v, ok := name2MessageAuthentication[string(text)]; ok {
		*this = v
		return nil
	}
	return fmt.Errorf("illegal ssh message authentication: %q", string(text))
}

func (this *MessageAuthentication) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this MessageAuthentication) IsZero() bool {
	return false
}

func (this MessageAuthentication) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case MessageAuthentication:
		return this.isEqualTo(&v)
	case *MessageAuthentication:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this MessageAuthentication) isEqualTo(other *MessageAuthentication) bool {
	return this == *other
}

type MessageAuthentications []MessageAuthentication

func (this MessageAuthentications) IsEmpty() bool {
	return len(this) == 0
}

func (this MessageAuthentications) IsCumulative() bool {
	return true
}

func (this MessageAuthentications) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this MessageAuthentications) MarshalTexts() (texts [][]byte, err error) {
	texts = make([][]byte, len(this))
	for i, v := range this {
		texts[i], err = v.MarshalText()
		if err != nil {
			return nil, fmt.Errorf("[%d] %w", i, err)
		}
	}
	return texts, nil
}
func (this MessageAuthentications) MarshalText() (text []byte, err error) {
	texts, err := this.MarshalTexts()
	if err != nil {
		return nil, err
	}
	return bytes.Join(texts, []byte(",")), nil
}

func (this MessageAuthentications) String() string {
	v, err := this.MarshalText()
	if err != nil {
		return fmt.Sprintf("illegal-ssh-message-authentications: %s", err.Error())
	}
	return string(v)
}

func (this *MessageAuthentications) UnmarshalText(text []byte) error {
	texts := bytes.Split(text, []byte(","))
	for _, v := range texts {
		var buf MessageAuthentication
		if err := buf.UnmarshalText(v); err != nil {
			return err
		}
		*this = append(*this, buf)
	}
	return nil
}

func (this *MessageAuthentications) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this MessageAuthentications) IsZero() bool {
	return false
}

func (this MessageAuthentications) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case MessageAuthentications:
		return this.isEqualTo(&v)
	case *MessageAuthentications:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this MessageAuthentications) isEqualTo(other *MessageAuthentications) bool {
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

func (this MessageAuthentications) Contains(v MessageAuthentication) bool {
	return slices.Contains(this, v)
}
