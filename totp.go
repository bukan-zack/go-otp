package otp

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"time"
)

type TOTP struct {
	secret []byte
	time   time.Time
	hash   Hash
	digits Digits
}

type TOTPOptions struct {
	Secret []byte
	Time   time.Time
	Hash   Hash
	Digits Digits
}

// NewTOTP returns a new TOTP. If you need more control over TOTP value, use NewCustomTOTP.
func NewTOTP() (*TOTP, error) {
	secret := make([]byte, HashSHA256.Size())
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}

	return NewCustomTOTP(TOTPOptions{
		Secret: secret,
		Time:   time.Now().UTC(),
		Hash:   HashSHA256,
		Digits: DigitsSix,
	}), nil
}

// NewCustomTOTP returns a new TOTP.
func NewCustomTOTP(opts TOTPOptions) *TOTP {
	t := &TOTP{
		secret: bytes.ToUpper(opts.Secret),
		time:   opts.Time,
		hash:   opts.Hash,
		digits: opts.Digits,
	}

	return t
}

// Secret returns the TOTP secret.
func (t *TOTP) Secret() []byte {
	return t.secret
}

// Time returns the TOTP time.
func (t *TOTP) Time() time.Time {
	return t.time
}

// Generate returns cryptographically generated TOTP value.
func (t *TOTP) Generate() (string, error) {
	counter := t.time.Unix() / 30

	return NewCustomHOTP(HOTPOptions{
		Secret:  t.secret,
		Counter: uint64(counter),
		Hash:    t.hash,
		Digits:  t.digits,
	}).Generate()
}

// Validate validates given TOTP code.
func (t *TOTP) Validate(code string) error {
	if len(code) != t.digits.Int() {
		return ErrInvalidCode
	}

	genCode, err := t.Generate()
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare([]byte(code), []byte(genCode)) == 0 {
		return ErrInvalidCode
	}

	return nil
}
