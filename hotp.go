package otp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"math"
	"strconv"
)

type HOTP struct {
	secret  []byte
	counter [8]byte
	hash    Hash
	digits  Digits
}

type HOTPOptions struct {
	Secret  []byte
	Counter uint64
	Hash    Hash
	Digits  Digits
}

// NewHOTP returns a new HOTP. If you need more control over HOTP value, use NewCustomHOTP.
func NewHOTP(counter uint64) (*HOTP, error) {
	secret := make([]byte, HashSHA1.Size())
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}

	return NewCustomHOTP(HOTPOptions{
		Secret:  secret,
		Counter: counter,
		Hash:    HashSHA1,
		Digits:  DigitsSix,
	}), nil
}

// NewCustomHOTP returns a new HOTP.
func NewCustomHOTP(opts HOTPOptions) *HOTP {
	h := &HOTP{
		secret: bytes.ToUpper(opts.Secret),
		hash:   opts.Hash,
		digits: opts.Digits,
	}

	binary.BigEndian.PutUint64(h.counter[:], opts.Counter)

	return h
}

// Secret returns the HOTP secret.
func (h *HOTP) Secret() []byte {
	return h.secret
}

// Counter returns the HOTP counter.
func (h *HOTP) Counter() uint64 {
	return binary.BigEndian.Uint64(h.counter[:])
}

// Generate returns cryptographically generated HOTP value.
func (h *HOTP) Generate() (string, error) {
	mac := hmac.New(h.hash.Hash, h.secret)
	mac.Write(h.counter[:])

	sum := mac.Sum(nil)

	// Dynamic truncation
	// https://www.rfc-editor.org/rfc/rfc4226#section-5.4
	offset := int(sum[len(sum)-1] & 0xf)
	binary := int(int((sum[offset]&0x7f))<<24 |
		(int(sum[offset+1]&0xff))<<16 |
		(int(sum[offset+2]&0xff))<<8 |
		(int(sum[offset+3] & 0xff)))

	code := binary % int(math.Pow10(h.digits.Int()))

	return strconv.Itoa(code), nil
}

// Validate validates given HOTP code.
func (h *HOTP) Validate(code string) error {
	if len(code) != h.digits.Int() {
		return ErrInvalidCode
	}

	genCode, err := h.Generate()
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare([]byte(code), []byte(genCode)) == 0 {
		return ErrInvalidCode
	}

	return nil
}
