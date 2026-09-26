package recording

import (
	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/errors"
)

type Id uuid.UUID

func NewId() (Id, error) {
	value, err := uuid.NewRandom()
	if err != nil {
		return Id{}, err
	}
	return Id(value), nil
}

func (this Id) String() string {
	return uuid.UUID(this).String()
}

func (this Id) IsZero() bool {
	return uuid.UUID(this) == uuid.Nil
}

func (this Id) MarshalText() ([]byte, error) {
	if err := validateId(this); err != nil {
		return nil, err
	}
	return []byte(this.String()), nil
}

func (this *Id) UnmarshalText(text []byte) error {
	value, err := uuid.Parse(string(text))
	if err != nil {
		return errors.Config.Newf("illegal recording ID: %w", err)
	}
	decoded := Id(value)
	if err := validateId(decoded); err != nil {
		return err
	}
	if decoded.String() != string(text) {
		return errors.Config.Newf("recording ID is not canonical")
	}
	*this = decoded
	return nil
}

func validateId(value Id) error {
	raw := uuid.UUID(value)
	if raw == uuid.Nil || raw.Version() != 4 || raw.Variant() != uuid.RFC4122 {
		return errors.Config.Newf("illegal recording ID %q", raw)
	}
	return nil
}
