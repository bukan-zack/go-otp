package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"math"
	"strconv"
)

type HOTP struct {
	secret  []byte
	counter [8]byte
	digits  Digits
	hash    Hash
}

type HOTPOptions struct {
	Secret  []byte // Secret between client and server. K in RFC 4226.
	Counter uint64 // The moving factor. C in RFC 4226.
	Digits  Digits // Number of digits in an HOTP code. Digit in RFC 4226.
	Hash    Hash   // Algorithm for the HOTP.
}

// NewHOTP returns a new HOTP.
func NewHOTP(opts HOTPOptions) (*HOTP, error) {
	h := &HOTP{
		secret: opts.Secret,
		digits: opts.Digits,
		hash:   opts.Hash,
	}

	if h.secret == nil {
		secret := make([]byte, h.hash.Size())
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	}

	binary.BigEndian.PutUint64(h.counter[:], opts.Counter)

	return h, nil
}

// SetSecret sets the secret for the HOTP.
func (h *HOTP) SetSecret(secret []byte) {
	h.secret = secret
}

// Secret returns the HOTP secret.
func (h *HOTP) Secret() []byte {
	return h.secret
}

// Base32Secret returns the HOTP secret encoded in base32.
func (h *HOTP) Base32Secret() string {
	return base32.StdEncoding.EncodeToString(h.secret)
}

// SetCounter sets the HOTP counter to given counter.
func (h *HOTP) SetCounter(counter uint64) {
	binary.BigEndian.PutUint64(h.counter[:], counter)
}

// Counter returns the HOTP counter.
func (h *HOTP) Counter() uint64 {
	return binary.BigEndian.Uint64(h.counter[:])
}

// SetDigits sets the HOTP digits.
func (h *HOTP) SetDigits(digits Digits) {
	h.digits = digits
}

// Digits returns the HOTP digits.
func (h *HOTP) Digits() Digits {
	return h.digits
}

// SetHash sets the hash algorithm for the HOTP.
func (h *HOTP) SetHash(hash Hash) {
	h.hash = hash
}

// Hash returns the HOTP hash algorithm.
func (h *HOTP) Hash() Hash {
	return h.hash
}

// Generate returns cryptographically generated HOTP code.
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
