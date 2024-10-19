package crypto

import (
	"encoding/asn1"
	"fmt"

	"github.com/engity-com/bifroest/pkg/errors"
)

type ObjectId uint8

const (
	ObjectIdEmpty = ObjectId(0)

	ObjectIdSessionId = ObjectId(1)
)

var (
	ErrIllegalObjectId = errors.Config.Newf("illegal object-id")

	objectIdId     = 2
	objectIdPrefix = PrefixWithEngityObjectId(asn1.ObjectIdentifier{objectIdId})

	objectIdToName = map[ObjectId]string{
		ObjectIdEmpty:     "",
		ObjectIdSessionId: "sessionId",
	}
	nameToObjectId = func(in map[ObjectId]string) map[string]ObjectId {
		result := make(map[string]ObjectId, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(objectIdToName)
)

func (this ObjectId) ToNative() (asn1.ObjectIdentifier, error) {
	if err := this.Validate(); err != nil {
		return asn1.ObjectIdentifier{}, err
	}
	return this.ToNativeDirect(), nil
}

func (this ObjectId) ToNativeDirect() asn1.ObjectIdentifier {
	return append(objectIdPrefix, int(this))
}

func (this *ObjectId) FromNative(in asn1.ObjectIdentifier) error {
	if len(in) == 0 {
		*this = 0
		return nil
	}
	rest := CutEngityObjectIdPrefix(in)
	if rest == nil || len(rest) != 2 || rest[0] != objectIdId || rest[1] >= 256 {
		return errors.Config.Newf("%w: %v", ErrIllegalObjectId, in)
	}
	buf := ObjectId(rest[1])
	if err := buf.Validate(); err != nil {
		return fmt.Errorf("%w: %v", err, in)
	}

	*this = buf
	return nil
}

func (this ObjectId) String() string {
	v, ok := objectIdToName[this]
	if !ok {
		return fmt.Sprintf("illegal-object-id-%d", this)
	}
	return v
}

func (this ObjectId) MarshalText() (text []byte, err error) {
	v, ok := objectIdToName[this]
	if !ok {
		return nil, errors.Config.Newf("%w: %d", ErrIllegalObjectId, this)
	}
	return []byte(v), nil
}

func (this *ObjectId) UnmarshalText(text []byte) error {
	v, ok := nameToObjectId[string(text)]
	if !ok {
		return errors.Config.Newf("%w: %s", ErrIllegalObjectId, string(text))
	}
	*this = v
	return nil
}

func (this *ObjectId) Set(plain string) error {
	return this.UnmarshalText([]byte(plain))
}

func (this ObjectId) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this ObjectId) IsZero() bool {
	return this == 0
}

func (this ObjectId) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case asn1.ObjectIdentifier:
		return this.isEqualToNative(&v)
	case *asn1.ObjectIdentifier:
		return this.isEqualToNative(v)
	case ObjectId:
		return this.isEqualTo(&v)
	case *ObjectId:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this ObjectId) isEqualTo(other *ObjectId) bool {
	return this == *other
}

func (this ObjectId) isEqualToNative(other *asn1.ObjectIdentifier) bool {
	var otherBuf ObjectId
	if err := otherBuf.FromNative(*other); err != nil {
		return false
	}
	return this.isEqualTo(&otherBuf)
}
