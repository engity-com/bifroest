package crypto

import (
	"golang.org/x/crypto/bcrypt"

	"github.com/engity-com/bifroest/pkg/errors"
)

func (this PasswordType) encodeBcrypt(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
}

func (this PasswordType) compareBcrypt(encoded, password []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(encoded, password)
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) || errors.Is(err, bcrypt.ErrHashTooShort) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}
